// Package vortexsrv is the exported entry point of the RayZen Vortex server
// (patches/0003-vortex-server.patch, new file). It wraps the StormDNS server with the
// Vortex options (response hold, zone answers) so a command outside this module
// (core/cmd/vortex-server) can run it.
package vortexsrv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"stormdns-go/internal/config"
	DnsParser "stormdns-go/internal/dnsparser"
	"stormdns-go/internal/logger"
	"stormdns-go/internal/security"
	"stormdns-go/internal/udpserver"
	"stormdns-go/internal/version"
)

// Settings are the VORTEX_* keys read from the same server TOML as the engine keys.
type Settings struct {
	HoldMaxMs         *int   `toml:"VORTEX_HOLD_MAX_MS"`
	HoldInitialMs     int    `toml:"VORTEX_HOLD_INITIAL_MS"`
	HoldStepMs        int    `toml:"VORTEX_HOLD_STEP_MS"`
	HoldMaxPerSession int    `toml:"VORTEX_HOLD_MAX_PER_SESSION"`
	HoldMaxTotal      int    `toml:"VORTEX_HOLD_MAX_TOTAL"`
	HoldTypes         string `toml:"VORTEX_HOLD_TYPES"` // "ping" (default) or "all"
	Authoritative     *bool  `toml:"VORTEX_AUTHORITATIVE"`
	NSHost            string `toml:"VORTEX_NS_HOST"`
	Hostmaster        string `toml:"VORTEX_HOSTMASTER"`
	Name              string `toml:"VORTEX_NAME"`
}

// DefaultHoldMaxMs is used when VORTEX_HOLD_MAX_MS is absent (chosen from docs/lab/VORTEX-SERVER.md).
const DefaultHoldMaxMs = 600

// DefaultHoldAll is the VORTEX_HOLD_TYPES default (false = PINGs only).
var DefaultHoldAll = false

// Stats is what `vortex-server status` prints.
type Stats struct {
	Version   string                `json:"version"`
	UptimeSec int64                 `json:"uptimeSec"`
	Domains   []string              `json:"domains"`
	Engine    udpserver.Stats       `json:"engine"`
	Vortex    udpserver.VortexStats `json:"vortex"`
	UpdatedAt time.Time             `json:"updatedAt"`
}

// Server is one configured Vortex server instance.
type Server struct {
	Cfg      config.ServerConfig
	Settings Settings
	Key      string
	srv      *udpserver.Server
	log      *logger.Logger
	started  time.Time
}

// LoadSettings reads only the VORTEX_* keys of a server TOML.
func LoadSettings(path string) (Settings, error) {
	var s Settings
	if _, err := toml.DecodeFile(path, &s); err != nil {
		return s, fmt.Errorf("parse %s: %w", path, err)
	}
	return s, nil
}

// HoldMax returns the effective maximum hold.
func (s Settings) HoldMax() time.Duration {
	ms := DefaultHoldMaxMs
	if s.HoldMaxMs != nil {
		ms = *s.HoldMaxMs
	}
	if ms < 0 {
		ms = 0
	}
	if ms > 3000 {
		ms = 3000 // resolvers give up long before this
	}
	return time.Duration(ms) * time.Millisecond
}

// HoldAll reports whether every post-session query may be parked (VORTEX_HOLD_TYPES = "all").
func (s Settings) HoldAll() bool {
	switch strings.ToLower(strings.TrimSpace(s.HoldTypes)) {
	case "all":
		return true
	case "":
		return DefaultHoldAll
	}
	return false // "ping" or unknown
}

// IsAuthoritative reports whether zone answers are on (default on).
func (s Settings) IsAuthoritative() bool { return s.Authoritative == nil || *s.Authoritative }

// Load reads the TOML, makes sure the key exists (it is never logged) and builds the server.
func Load(path string) (*Server, error) {
	cfg, err := config.LoadServerConfig(path)
	if err != nil {
		return nil, err
	}
	if len(cfg.Domain) == 0 {
		return nil, errors.New("DOMAIN is empty")
	}
	st, err := LoadSettings(path)
	if err != nil {
		return nil, err
	}
	keyInfo, err := security.EnsureServerEncryptionKey(cfg)
	if err != nil {
		return nil, err
	}
	codec, err := security.NewCodecFromConfig(cfg, keyInfo.Key)
	if err != nil {
		return nil, err
	}
	log := logger.New("Vortex Server", cfg.LogLevel)
	srv := udpserver.New(cfg, log, codec)
	opts := udpserver.VortexOptions{
		HoldMax:           st.HoldMax(),
		HoldInitial:       time.Duration(st.HoldInitialMs) * time.Millisecond,
		HoldStep:          time.Duration(st.HoldStepMs) * time.Millisecond,
		HoldMaxPerSession: st.HoldMaxPerSession,
		HoldMaxTotal:      st.HoldMaxTotal,
		HoldAllTypes:      st.HoldAll(),
	}
	if st.IsAuthoritative() {
		serial := uint32(time.Now().UTC().Year()*1000000 + int(time.Now().UTC().Month())*10000 + time.Now().UTC().Day()*100 + 1)
		for _, d := range cfg.Domain {
			opts.Zone = append(opts.Zone, ZoneFor(d, st, serial))
		}
	}
	srv.EnableVortex(opts)
	return &Server{Cfg: cfg, Settings: st, Key: keyInfo.Key, srv: srv, log: log}, nil
}

// ZoneFor returns the zone data published for one tunnel domain.
func ZoneFor(domain string, st Settings, serial uint32) DnsParser.ZoneInfo {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	parent := d
	if i := strings.IndexByte(d, '.'); i > 0 && strings.Contains(d[i+1:], ".") {
		parent = d[i+1:]
	}
	ns := st.NSHost
	if ns == "" {
		ns = "ns." + parent
	}
	hm := st.Hostmaster
	if hm == "" {
		hm = "hostmaster." + parent
	}
	return DnsParser.ZoneInfo{Zone: d, NSHost: ns, Hostmaster: hm, Serial: serial, TTL: 3600, NegTTL: 60}
}

// Run serves until ctx ends. Zone answers switch authoritative flags on for this process.
func (s *Server) Run(ctx context.Context) error {
	if s.Settings.IsAuthoritative() {
		DnsParser.SetAuthoritativeResponses(true)
	}
	s.started = time.Now()
	s.log.Infof("<green>RayZen Vortex server %s (engine StormDNS %s) on %s, domains %s, hold max %v (all types %v), zone answers %v</green>",
		Version, version.GetVersion(), s.Cfg.Address(), strings.Join(s.Cfg.Domain, ", "), s.Settings.HoldMax(), s.Settings.HoldAll(), s.Settings.IsAuthoritative())
	err := s.srv.RunContext(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// Stats returns a snapshot.
func (s *Server) Stats() Stats {
	st := Stats{Version: Version, Domains: append([]string(nil), s.Cfg.Domain...), Engine: s.srv.Stats(), Vortex: s.srv.VortexStats(), UpdatedAt: time.Now().UTC()}
	if !s.started.IsZero() {
		st.UptimeSec = int64(time.Since(s.started).Seconds())
	}
	return st
}

// Version is the Vortex server version (set by the build with -ldflags -X).
var Version = "2.0.2"

// KeyLength is the key length the engine expects for an encryption method.
func KeyLength(method int) int {
	switch method {
	case 3:
		return 16
	case 4:
		return 24
	default:
		return 32
	}
}

// ReadKey reads the key file of a config without generating one.
func ReadKey(cfg config.ServerConfig) (string, error) {
	raw, err := os.ReadFile(cfg.EncryptionKeyPath())
	if err != nil {
		return "", err
	}
	k := strings.TrimSpace(string(raw))
	if len(k) != KeyLength(cfg.DataEncryptionMethod) {
		return "", fmt.Errorf("key in %s has the wrong length for method %d", cfg.EncryptionKeyPath(), cfg.DataEncryptionMethod)
	}
	return k, nil
}

// LoadConfig loads only the engine config (no key generation).
func LoadConfig(path string) (config.ServerConfig, error) { return config.LoadServerConfig(path) }

// EngineVersion is the vendored StormDNS version string.
func EngineVersion() string { return version.GetVersion() }

// EnsureKey creates the key file of a config when it is missing or invalid (rotate: always
// a new key). It reports whether a key was generated and where it lives.
func EnsureKey(path string, rotate bool) (bool, string, error) {
	cfg, err := config.LoadServerConfig(path)
	if err != nil {
		return false, "", err
	}
	if rotate {
		if err := os.Remove(cfg.EncryptionKeyPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, "", err
		}
	}
	info, err := security.EnsureServerEncryptionKey(cfg)
	if err != nil {
		return false, "", err
	}
	_ = os.Chmod(info.Path, 0o600)
	return info.Generated, info.Path, nil
}
