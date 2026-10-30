package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"stormdns-go/vortexsrv"
)

func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	oldOut, oldErr := stdout, stderr
	stdout, stderr = &b, &b
	t.Cleanup(func() { stdout, stderr = oldOut, oldErr })
	return &b
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func initServer(t *testing.T, port int, domains ...string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "server.toml")
	args := []string{"init", "--config", cfg, "--port", strconv.Itoa(port)}
	for _, d := range domains {
		args = append(args, "--domain", d)
	}
	out := capture(t)
	if rc := dispatch(args); rc != 0 {
		t.Fatalf("init rc=%d: %s", rc, out)
	}
	return cfg
}

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{"T.Example.COM.": "t.example.com", " t-1.a.io ": "t-1.a.io"}
	for in, want := range good {
		if got, err := normalizeDomain(in); err != nil || got != want {
			t.Fatalf("normalizeDomain(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "localhost", "a..b.com", "-a.b.com", "a_b.c.com", strings.Repeat("a", 64) + ".com"} {
		if _, err := normalizeDomain(bad); err == nil {
			t.Fatalf("normalizeDomain(%q) should fail", bad)
		}
	}
	ds, err := normalizeDomains([]string{"A.b.com", "a.B.com.", "c.d.net"})
	if err != nil || strings.Join(ds, ",") != "a.b.com,c.d.net" {
		t.Fatalf("dedupe: %v %v", ds, err)
	}
}

func TestSetTOMLKeyKeepsComments(t *testing.T) {
	in := "# head\nDOMAIN = [\"a.b.com\"]\n# DOMAIN = commented\nUDP_PORT = 53\n"
	out := setTOMLKey(in, "DOMAIN", `["x.y.com", "z.w.net"]`)
	if !strings.Contains(out, "DOMAIN = [\"x.y.com\", \"z.w.net\"]\n") || !strings.Contains(out, "# DOMAIN = commented") || !strings.Contains(out, "UDP_PORT = 53") {
		t.Fatalf("unexpected:\n%s", out)
	}
	out = setTOMLKey(out, "VORTEX_NS_HOST", `"ns.b.com"`)
	if !strings.HasSuffix(out, "VORTEX_NS_HOST = \"ns.b.com\"\n") {
		t.Fatalf("append failed:\n%s", out)
	}
}

func TestDifferentDelegationsDoNotOverwriteGlobalNS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	original := "VORTEX_NS_HOST = \"\"\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	out := capture(t)
	storeNSHost(path, vortexsrv.Settings{}, []checkResult{
		{domain: "a.example.com", delegated: true, nsHost: "custom.example.com"},
		{domain: "b.example.net", delegated: true, nsHost: "ns.example.net"},
	})
	got, err := os.ReadFile(path)
	if err != nil || string(got) != original || !strings.Contains(out.String(), "different nameserver hosts") {
		t.Fatalf("different delegations were not preserved: %q %q %v", got, out.String(), err)
	}
}

func TestInitWritesLoadableConfigAndKey(t *testing.T) {
	cfg := initServer(t, 15399, "T.Example.com", "t2.example.net")
	c, err := vortexsrv.LoadConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Domain, ",") != "t.example.com,t2.example.net" || c.UDPPort != 15399 || c.DataEncryptionMethod != 5 {
		t.Fatalf("config %+v", c)
	}
	if len(c.SupportedUploadCompressionTypes) != 4 || c.ARQInitialRTOSeconds != 0.6 {
		t.Fatalf("tuned values not applied: %+v", c)
	}
	st, err := vortexsrv.LoadSettings(cfg)
	if err != nil || st.HoldMax() != vortexsrv.DefaultHoldMaxMs*time.Millisecond || !st.IsAuthoritative() {
		t.Fatalf("settings %+v %v", st, err)
	}
	key, err := vortexsrv.ReadKey(c)
	if err != nil || len(key) != 32 {
		t.Fatalf("key %q %v", key, err)
	}
	fi, _ := os.Stat(c.EncryptionKeyPath())
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode().Perm())
	}
	// A second init refuses to overwrite; --force keeps the key.
	out := capture(t)
	if rc := dispatch([]string{"init", "--config", cfg, "--domain", "x.y.com"}); rc == 0 {
		t.Fatal("second init must fail without --force")
	}
	if rc := dispatch([]string{"init", "--config", cfg, "--domain", "x.y.com", "--force"}); rc != 0 {
		t.Fatalf("force: %s", out)
	}
	c2, _ := vortexsrv.LoadConfig(cfg)
	if k2, _ := vortexsrv.ReadKey(c2); k2 != key || strings.Join(c2.Domain, ",") != "x.y.com" {
		t.Fatalf("force init changed the key or kept old domains: %v", c2.Domain)
	}
}

func TestInitImportsLegacyKey(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "encrypt_key.txt")
	_ = os.WriteFile(legacy, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	cfg := filepath.Join(dir, "new", "server.toml")
	out := capture(t)
	if rc := dispatch([]string{"init", "--config", cfg, "--domain", "t.a.com", "--key-from", legacy}); rc != 0 {
		t.Fatalf("rc=%d %s", rc, out)
	}
	if !strings.Contains(out.String(), "existing key kept") {
		t.Fatalf("output: %s", out)
	}
	c, _ := vortexsrv.LoadConfig(cfg)
	if k, _ := vortexsrv.ReadKey(c); k != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("key not imported: %q", k)
	}
	_ = os.WriteFile(legacy, []byte("short"), 0o600)
	if rc := dispatch([]string{"init", "--config", filepath.Join(dir, "b.toml"), "--domain", "t.a.com", "--key-from", legacy}); rc == 0 {
		t.Fatal("a wrong-length legacy key must be refused")
	}
}

func TestDomainAddRemove(t *testing.T) {
	cfg := initServer(t, 15398, "a.b.com")
	out := capture(t)
	if rc := dispatch([]string{"domain", "add", "C.D.net", "--config", cfg}); rc != 0 {
		t.Fatalf("add: %s", out)
	}
	c, _ := vortexsrv.LoadConfig(cfg)
	if strings.Join(c.Domain, ",") != "a.b.com,c.d.net" {
		t.Fatalf("after add: %v", c.Domain)
	}
	if rc := dispatch([]string{"domain", "remove", "--config", cfg, "a.b.com"}); rc != 0 {
		t.Fatalf("remove: %s", out)
	}
	c, _ = vortexsrv.LoadConfig(cfg)
	if strings.Join(c.Domain, ",") != "c.d.net" {
		t.Fatalf("after remove: %v", c.Domain)
	}
	if rc := dispatch([]string{"domain", "remove", "--config", cfg, "c.d.net"}); rc == 0 {
		t.Fatal("removing the last domain must fail")
	}
	raw, _ := os.ReadFile(cfg)
	if !strings.Contains(string(raw), "# ---- Vortex additions ----") {
		t.Fatal("comments lost on rewrite")
	}
}

func TestKeygenRotate(t *testing.T) {
	cfg := initServer(t, 15397, "a.b.com")
	c, _ := vortexsrv.LoadConfig(cfg)
	k1, _ := vortexsrv.ReadKey(c)
	out := capture(t)
	if rc := dispatch([]string{"keygen", "--config", cfg}); rc != 0 || !strings.Contains(out.String(), "already exists") {
		t.Fatalf("keygen: %s", out)
	}
	if rc := dispatch([]string{"keygen", "--config", cfg, "--rotate"}); rc != 0 {
		t.Fatalf("rotate: %s", out)
	}
	k2, _ := vortexsrv.ReadKey(c)
	if k2 == k1 || len(k2) != 32 {
		t.Fatalf("rotate did not make a new key")
	}
}

func TestLinkRoundTripV2(t *testing.T) {
	cfg := initServer(t, 15396, "t.example.com", "t2.example.net")
	out := capture(t)
	if rc := dispatch([]string{"link", "-q", "--config", cfg, "--name", "Home VPS"}); rc != 0 {
		t.Fatalf("link: %s", out)
	}
	link := strings.TrimSpace(out.String())
	if !strings.HasPrefix(link, "vortex://p/") || strings.ContainsAny(strings.TrimPrefix(link, "vortex://p/"), "+/= \n") {
		t.Fatalf("link must be one unpadded base64url line: %q", link)
	}
	r, err := parseLink(link)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := vortexsrv.LoadConfig(cfg)
	key, _ := vortexsrv.ReadKey(c)
	p := r.Profile
	if r.Schema != "whitedns.profile" || r.Version != 2 || p.Engine != "stormdns" || p.Name != "Home VPS" {
		t.Fatalf("root %+v", r)
	}
	if p.Server.Domain != "t.example.com" || strings.Join(p.Server.Domains, ",") != "t.example.com,t2.example.net" ||
		p.Server.EncryptionKey != key || p.Server.EncryptionMethod != 5 {
		t.Fatalf("server %+v", p.Server)
	}
	if p.Vortex.MinApp != "1.4.0" || p.Vortex.HoldMaxMs != vortexsrv.DefaultHoldMaxMs || p.Resolvers == nil {
		t.Fatalf("vortex block %+v", p.Vortex)
	}
	// Default name comes from VORTEX_NAME.
	out.Reset()
	_ = dispatch([]string{"link", "-q", "--config", cfg})
	r2, _ := parseLink(strings.TrimSpace(out.String()))
	if r2.Profile.Name != "Vortex t.example.com" {
		t.Fatalf("default name %q", r2.Profile.Name)
	}
	// The human output has exactly one link line (copyable; no QR, D-31).
	out.Reset()
	_ = dispatch([]string{"link", "--config", cfg})
	lines := 0
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "vortex://p/") {
			lines++
		}
	}
	if lines != 1 || strings.Count(out.String(), "vortex://p/") != 1 {
		t.Fatalf("want exactly one link line:\n%s", out)
	}
}

func TestLinkWithoutKeyFails(t *testing.T) {
	cfg := initServer(t, 15395, "a.b.com")
	c, _ := vortexsrv.LoadConfig(cfg)
	_ = os.Remove(c.EncryptionKeyPath())
	out := capture(t)
	if rc := dispatch([]string{"link", "--config", cfg}); rc == 0 || !strings.Contains(out.String(), "keygen") {
		t.Fatalf("expected a keygen hint, got rc=%d %s", rc, out)
	}
}

func TestNotifierAndWatchdogInterval(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "vxn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "n.sock")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	t.Setenv("NOTIFY_SOCKET", sock)
	if err := newNotifier().send("READY=1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = l.SetReadDeadline(time.Now().Add(time.Second))
	n, err := l.Read(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Fatalf("got %q %v", buf[:n], err)
	}
	t.Setenv("NOTIFY_SOCKET", "")
	if newNotifier() != nil || newNotifier().send("X=1") != nil {
		t.Fatal("no socket: notifier must be a no-op")
	}
	t.Setenv("WATCHDOG_USEC", "20000000")
	t.Setenv("WATCHDOG_PID", "")
	if iv := watchdogInterval(); iv != 10*time.Second {
		t.Fatalf("interval %v", iv)
	}
	t.Setenv("WATCHDOG_PID", "1")
	if watchdogInterval() != 0 {
		t.Fatal("watchdog meant for another pid must be ignored")
	}
}

// TestRunServesSelfcheckAndStatus runs the real server in-process: readiness (sd_notify),
// zone answers, a real tunnel handshake with the engine's client probes, and status.
func TestRunServesSelfcheckAndStatus(t *testing.T) {
	port := freeUDPPort(t)
	cfg := initServer(t, port, "t.example.com")
	dir, err := os.MkdirTemp("/tmp", "vxr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "n.sock")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	t.Setenv("NOTIFY_SOCKET", sock)
	t.Setenv("WATCHDOG_USEC", "400000")
	t.Setenv("WATCHDOG_PID", "")
	stats := filepath.Join(dir, "stats.json")

	out := capture(t)
	done := make(chan int, 1)
	go func() { done <- dispatch([]string{"run", "--config", cfg, "--stats", stats}) }()

	got := map[string]bool{}
	deadline := time.Now().Add(8 * time.Second)
	buf := make([]byte, 256)
	for time.Now().Before(deadline) && !(got["READY=1"] && got["WATCHDOG=1"]) {
		_ = l.SetReadDeadline(time.Now().Add(time.Second))
		n, err := l.Read(buf)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			got[line] = true
		}
	}
	if !got["READY=1"] || !got["WATCHDOG=1"] {
		t.Fatalf("notify messages %v", got)
	}

	// Zone answer: apex SOA is authoritative.
	m, err := queryDNS(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "t.example.com", typeSOA, time.Second)
	if err != nil || !m.Authoritative || len(m.Answers) != 1 {
		t.Fatalf("SOA answer %+v %v", m, err)
	}

	if rc := dispatch([]string{"selfcheck", "--config", cfg}); rc != 0 || !strings.Contains(out.String(), "[ok] t.example.com: tunnel handshake") {
		t.Fatalf("selfcheck rc=%d:\n%s", rc, out)
	}
	out.Reset()
	if rc := dispatch([]string{"status", "--stats", stats}); rc != 0 || !strings.Contains(out.String(), "Domains: t.example.com") {
		t.Fatalf("status rc=%d:\n%s", rc, out)
	}

	select {
	case rc := <-done:
		t.Fatalf("server exited early rc=%d", rc)
	default:
	}
	// SIGTERM (what systemd sends) stops the server cleanly and removes the stats file.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case rc := <-done:
		if rc != 0 {
			t.Fatalf("run exited rc=%d:\n%s", rc, out)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("run did not stop on SIGTERM")
	}
	if _, err := os.Stat(stats); !os.IsNotExist(err) {
		t.Fatalf("stats file left behind: %v", err)
	}
	if !got["STOPPING=1"] {
		_ = l.SetReadDeadline(time.Now().Add(time.Second))
		for {
			n, err := l.Read(buf)
			if err != nil {
				break
			}
			if strings.Contains(string(buf[:n]), "STOPPING=1") {
				got["STOPPING=1"] = true
				break
			}
		}
	}
	if !got["STOPPING=1"] {
		t.Fatal("no STOPPING=1 notification")
	}
}

func TestSelfcheckFailsWhenNothingListens(t *testing.T) {
	port := freeUDPPort(t)
	cfg := initServer(t, port, "t.example.com")
	out := capture(t)
	old := newProber
	t.Cleanup(func() { newProber = old })
	newProber = func(_, _ string, _ int) (prober, error) { return fakeProber{}, nil }
	if rc := dispatch([]string{"selfcheck", "--config", cfg}); rc != 4 || !strings.Contains(out.String(), "[!!]") {
		t.Fatalf("rc=%d %s", rc, out)
	}
}

func TestSelfcheckRejectsFailedSessionAfterSuccessfulMTU(t *testing.T) {
	cfg := initServer(t, freeUDPPort(t), "t.example.com")
	out := capture(t)
	oldProber, oldSession := newProber, probeSession
	t.Cleanup(func() { newProber, probeSession = oldProber, oldSession })
	newProber = func(_, _ string, _ int) (prober, error) { return successfulProber{}, nil }
	probeSession = func(context.Context, string, string, int, string, int, int) error {
		return errors.New("session rejected")
	}
	if rc := dispatch([]string{"selfcheck", "--config", cfg}); rc != 4 || !strings.Contains(out.String(), "MTU probes passed but session initialization failed") {
		t.Fatalf("selfcheck must fail after rejected session: rc=%d %s", rc, out)
	}
}

type successfulProber struct{}

func (successfulProber) ProbeFixed(context.Context, string, int, int, int, time.Duration) (bool, time.Duration) {
	return true, time.Millisecond
}
func (successfulProber) Discover(context.Context, string, int) (int, int, int, time.Duration, bool) {
	return 100, 0, 500, time.Millisecond, true
}

func TestSessionProbeAgainstServer(t *testing.T) {
	addr, key := runServer(t, "a.example.com", "b.example.net")
	for _, domain := range []string{"a.example.com", "b.example.net"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := vortexsrv.ProbeSession(ctx, addr, domain, 5, key, 100, 500)
		cancel()
		if err != nil {
			t.Fatalf("session %s: %v", domain, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := vortexsrv.ProbeSession(ctx, addr, "a.example.com", 5, "incorrect-key-000000000000000000", 100, 500); err == nil {
		t.Fatal("session accepted with wrong key")
	}
}

func TestInvalidExistingKeyIsNotReplaced(t *testing.T) {
	cfg := initServer(t, freeUDPPort(t), "t.example.com")
	c, err := vortexsrv.LoadConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.EncryptionKeyPath(), []byte("invalid-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vortexsrv.EnsureKey(cfg, false); err == nil {
		t.Fatal("invalid existing key should fail")
	}
	if _, err := vortexsrv.Load(cfg); err == nil {
		t.Fatal("server should fail with an invalid existing key")
	}
	data, err := os.ReadFile(c.EncryptionKeyPath())
	if err != nil || string(data) != "invalid-key" {
		t.Fatalf("key changed: %q, %v", data, err)
	}
}

type fakeProber struct{}

func (fakeProber) ProbeFixed(context.Context, string, int, int, int, time.Duration) (bool, time.Duration) {
	return false, 0
}

func (fakeProber) Discover(context.Context, string, int) (int, int, int, time.Duration, bool) {
	return 0, 0, 0, 0, false
}

func TestDispatchUsageAndUnknown(t *testing.T) {
	out := capture(t)
	if dispatch(nil) != 2 || dispatch([]string{"nope"}) != 2 {
		t.Fatal("bad usage must exit 2")
	}
	if dispatch([]string{"--help"}) != 0 || !strings.Contains(out.String(), "check-dns") {
		t.Fatal("help")
	}
	if dispatch([]string{"link", "-h"}) != 0 {
		t.Fatal("-h exits 0")
	}
	if dispatch([]string{"init", "--config", filepath.Join(t.TempDir(), "x.toml")}) != 1 {
		t.Fatal("init without --domain exits 1")
	}
}

func TestDiagnosticProberInitialization(t *testing.T) {
	if _, err := newProber("t.example.com", "0123456789abcdef0123456789abcdef", 5); err != nil {
		t.Fatalf("prober from the selfcheck client config: %v", err)
	}
}
