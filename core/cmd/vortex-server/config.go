package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"stormdns-go/vortexsrv"
)

// encryptionMethod is fixed for new servers: AES-256-GCM (engine method 5).
const encryptionMethod = 5

// configTemplate is the tuned server config written by `init`. Keys not listed keep the
// engine defaults. Values marked (sample) are the upstream sample values that the earlier
// RayZen installer shipped; the VORTEX_* block is read by vortexsrv only.
const configTemplate = `# RayZen Vortex server config (written by 'vortex-server init').
# Change domains with 'vortex-server domain add|remove', then: systemctl restart vortex-server
DOMAIN = %s
UDP_HOST = "0.0.0.0"
UDP_PORT = %d
PROTOCOL_TYPE = "SOCKS5"

# Encryption: AES-256-GCM with the key in ENCRYPTION_KEY_FILE (never share the file, only the link).
DATA_ENCRYPTION_METHOD = %d
ENCRYPTION_KEY_FILE = "key.txt"

# Every compression the app may ask for (sample).
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]

# Socket and queues (the installer raises the kernel UDP buffer limits to match).
SOCKET_BUFFER_SIZE = 8388608
MAX_CONCURRENT_REQUESTS = 16384
MAX_PACKETS_PER_BATCH = 10

# Where tunnelled DNS lookups and TCP connects go.
DNS_UPSTREAM_SERVERS = ["1.1.1.1:53", "8.8.8.8:53"]
DNS_UPSTREAM_TIMEOUT = 4.0
SOCKS_CONNECT_TIMEOUT = 10.0

# Retransmission tuned for lossy resolver paths (sample): fast first retry, NACK on gaps.
ARQ_WINDOW_SIZE = 1000
ARQ_INITIAL_RTO_SECONDS = 0.6
ARQ_MAX_RTO_SECONDS = 3.0
ARQ_CONTROL_INITIAL_RTO_SECONDS = 0.5
ARQ_CONTROL_MAX_RTO_SECONDS = 2.0
ARQ_MAX_CONTROL_RETRIES = 120
ARQ_MAX_DATA_RETRIES = 120
ARQ_DATA_NACK_MAX_GAP = 64
ARQ_DATA_NACK_INITIAL_DELAY_SECONDS = 0.4
ARQ_DATA_NACK_REPEAT_SECONDS = 0.8

LOG_LEVEL = "INFO"

# ---- Vortex additions ----
# Response hold: an idle poll waits up to this long for data instead of returning empty.
# The hold adapts per resolver (halved when a resolver re-sends, grows while clean). 0 = off.
VORTEX_HOLD_MAX_MS = %d
# Answer SOA/NS/A for the zone like a normal authoritative name server.
VORTEX_AUTHORITATIVE = true
# Name server host published in SOA/NS answers (empty = ns.<parent zone>).
# 'vortex-server check-dns --write-ns-host' fills it from your real delegation.
VORTEX_NS_HOST = %s
# Profile name shown in the app when the link is imported.
VORTEX_NAME = %s
`

var (
	labelRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	keyLines = map[string]*regexp.Regexp{}
)

// normalizeDomain lowercases, trims the root dot and validates a tunnel domain.
func normalizeDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if d == "" {
		return "", errors.New("empty domain")
	}
	if len(d) > 100 {
		return "", fmt.Errorf("domain %q is too long (max 100 characters; shorter domains carry more data)", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain %q must look like t.example.com", d)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", fmt.Errorf("domain %q has an invalid label %q", d, l)
		}
	}
	return d, nil
}

func normalizeDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		n, err := normalizeDomain(d)
		if err != nil {
			return nil, err
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func tomlString(s string) string { return strconv.Quote(s) }

func tomlList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = tomlString(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func renderConfig(domains []string, port int, nsHost, name string) string {
	if name == "" {
		name = "Vortex " + domains[0]
	}
	return fmt.Sprintf(configTemplate, tomlList(domains), port, encryptionMethod, vortexsrv.DefaultHoldMaxMs, tomlString(nsHost), tomlString(name))
}

func keyLineRe(key string) *regexp.Regexp {
	if re, ok := keyLines[key]; ok {
		return re
	}
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*=.*$`)
	keyLines[key] = re
	return re
}

// setTOMLKey replaces (or appends) one top-level `KEY = value` line, keeping comments.
func setTOMLKey(text, key, literal string) string {
	line := key + " = " + literal
	re := keyLineRe(key)
	if re.MatchString(text) {
		return re.ReplaceAllLiteralString(text, line)
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return text + line + "\n"
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil {
		_ = os.Chmod(name, fi.Mode().Perm()) // keep the operator's permissions on rewrite
		if st, ok := statOwner(fi); ok {
			_ = os.Chown(name, st.uid, st.gid)
		}
	}
	return os.Rename(name, path)
}

func cmdInit(args []string) error {
	fs := newFlags("init")
	cfgPath := fs.String("config", defaultConfig, "config file to create")
	var domains multiFlag
	fs.Var(&domains, "domain", "tunnel domain delegated to this server (repeat for more)")
	port := fs.Int("port", 53, "UDP port")
	nsHost := fs.String("ns-host", "", "name server host of the delegation (default ns.<parent zone>)")
	name := fs.String("name", "", "profile name shown in the app")
	keyFrom := fs.String("key-from", "", "reuse the key in this file (upgrade from an older server)")
	force := fs.Bool("force", false, "overwrite an existing config (the key is kept)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(domains) == 0 {
		return errors.New("at least one --domain is required")
	}
	ds, err := normalizeDomains(domains)
	if err != nil {
		return err
	}
	if *port <= 0 || *port > 65535 {
		return fmt.Errorf("invalid --port %d", *port)
	}
	if *nsHost != "" {
		n, err := normalizeDomain(*nsHost)
		if err != nil {
			return fmt.Errorf("--ns-host: %w", err)
		}
		*nsHost = n
	}
	path := absConfig(*cfgPath)
	if _, err := os.Stat(path); err == nil && !*force {
		return fmt.Errorf("%s already exists (use 'domain add' to add domains, or --force to rewrite it)", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := writeFileAtomic(path, []byte(renderConfig(ds, *port, *nsHost, *name)), 0o640); err != nil {
		return err
	}
	if *keyFrom != "" {
		if err := importKey(path, *keyFrom); err != nil {
			return err
		}
	}
	generated, keyPath, err := vortexsrv.EnsureKey(path, false)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "config written: %s\n", path)
	fmt.Fprintf(stdout, "domains: %s\n", strings.Join(ds, ", "))
	if generated {
		fmt.Fprintf(stdout, "new key created: %s\n", keyPath)
	} else {
		fmt.Fprintf(stdout, "existing key kept: %s\n", keyPath)
	}
	return nil
}

// importKey copies a key from an older install into this config's key file.
func importKey(cfgPath, from string) error {
	raw, err := os.ReadFile(from)
	if err != nil {
		return fmt.Errorf("read --key-from: %w", err)
	}
	k := strings.TrimSpace(string(raw))
	if len(k) != vortexsrv.KeyLength(encryptionMethod) || strings.ContainsAny(k, " \t\r\n") {
		return fmt.Errorf("key in %s has the wrong length for AES-256 (%d characters needed)", from, vortexsrv.KeyLength(encryptionMethod))
	}
	cfg, err := vortexsrv.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	return writeFileAtomic(cfg.EncryptionKeyPath(), []byte(k), 0o600)
}

func cmdKeygen(args []string) error {
	fs := newFlags("keygen")
	cfgPath := fs.String("config", defaultConfig, "server config")
	rotate := fs.Bool("rotate", false, "replace the key (every existing link stops working)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	generated, keyPath, err := vortexsrv.EnsureKey(absConfig(*cfgPath), *rotate)
	if err != nil {
		return err
	}
	switch {
	case *rotate:
		fmt.Fprintf(stdout, "new key created: %s (old links no longer work; share the new link)\n", keyPath)
	case generated:
		fmt.Fprintf(stdout, "new key created: %s\n", keyPath)
	default:
		fmt.Fprintf(stdout, "key already exists: %s\n", keyPath)
	}
	return nil
}

func cmdDomain(args []string) error {
	fs := newFlags("domain")
	cfgPath := fs.String("config", defaultConfig, "server config")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return errors.New("usage: vortex-server domain add|remove|list [domain...]")
	}
	path := absConfig(*cfgPath)
	cfg, err := vortexsrv.LoadConfig(path)
	if err != nil {
		return err
	}
	cur := append([]string(nil), cfg.Domain...)
	switch pos[0] {
	case "list", "ls":
		for _, d := range cur {
			fmt.Fprintln(stdout, d)
		}
		return nil
	case "add":
		add, err := normalizeDomains(pos[1:])
		if err != nil {
			return err
		}
		if len(add) == 0 {
			return errors.New("give the domain to add")
		}
		next, _ := normalizeDomains(append(cur, add...))
		return writeDomains(path, next)
	case "remove", "rm":
		rm, err := normalizeDomains(pos[1:])
		if err != nil {
			return err
		}
		drop := map[string]bool{}
		for _, d := range rm {
			drop[d] = true
		}
		var next []string
		for _, d := range cur {
			if n, _ := normalizeDomain(d); !drop[n] {
				next = append(next, d)
			}
		}
		if len(next) == len(cur) {
			return fmt.Errorf("%s is not configured", strings.Join(rm, ", "))
		}
		if len(next) == 0 {
			return errors.New("cannot remove the last domain")
		}
		return writeDomains(path, next)
	}
	return fmt.Errorf("unknown domain action %q (add, remove, list)", pos[0])
}

func writeDomains(path string, domains []string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out := setTOMLKey(string(raw), "DOMAIN", tomlList(domains))
	if err := writeFileAtomic(path, []byte(out), 0o640); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "domains: %s\n", strings.Join(domains, ", "))
	fmt.Fprintln(stdout, "restart to apply: systemctl restart vortex-server   (then share the new link)")
	return nil
}

func version() string { return vortexsrv.Version }

func cmdVersion(args []string) error {
	fs := newFlags("version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "vortex-server %s (engine StormDNS %s)\n", version(), vortexsrv.EngineVersion())
	return nil
}
