package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"stormdns-go/vortexsrv"
)

// ---- systemd notify protocol (sd_notify(3)), no libsystemd needed ----

type notifier struct{ addr *net.UnixAddr }

func newNotifier() *notifier {
	p := os.Getenv("NOTIFY_SOCKET")
	if p == "" {
		return nil
	}
	if p[0] == '@' { // abstract namespace
		p = "\x00" + p[1:]
	}
	return &notifier{addr: &net.UnixAddr{Name: p, Net: "unixgram"}}
}

func (n *notifier) send(state string) error {
	if n == nil {
		return nil
	}
	c, err := net.DialUnix("unixgram", nil, n.addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}

// watchdogInterval returns how often to ping the systemd watchdog (half of WATCHDOG_USEC),
// or 0 when the watchdog is off or meant for another process.
func watchdogInterval() time.Duration {
	us, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || us <= 0 {
		return 0
	}
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}
	return time.Duration(us) * time.Microsecond / 2
}

// probeAddr is where the local liveness probe is sent.
func probeAddr(host string, port int) string {
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func defaultStatsPath(cfgPath string) string {
	if d := os.Getenv("RUNTIME_DIRECTORY"); d != "" { // systemd RuntimeDirectory=
		return filepath.Join(strings.Split(d, ":")[0], "stats.json")
	}
	return filepath.Join(filepath.Dir(cfgPath), "stats.json")
}

func cmdRun(args []string) error {
	fs := newFlags("run")
	cfgPath := fs.String("config", defaultConfig, "server config")
	statsPath := fs.String("stats", "", "live counters file for 'status' (default $RUNTIME_DIRECTORY/stats.json or next to the config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := absConfig(*cfgPath)
	srv, err := vortexsrv.Load(path)
	if err != nil {
		return err
	}
	if *statsPath == "" {
		*statsPath = defaultStatsPath(path)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	n := newNotifier()
	errc := make(chan error, 1)
	go func() { errc <- srv.Run(ctx) }()

	addr := probeAddr(srv.Cfg.UDPHost, srv.Cfg.UDPPort)
	zone := srv.Cfg.Domain[0]
	if err := waitReady(ctx, addr, zone, errc, 15*time.Second); err != nil {
		_ = n.send("STATUS=failed to start: " + err.Error())
		stop()
		return err
	}
	_ = n.send(fmt.Sprintf("READY=1\nSTATUS=serving %s on %s", strings.Join(srv.Cfg.Domain, ", "), srv.Cfg.Address()))

	go statsLoop(ctx, srv, *statsPath)
	if iv := watchdogInterval(); iv > 0 && n != nil {
		go watchdogLoop(ctx, n, iv, addr, zone)
	}

	select {
	case err := <-errc:
		_ = os.Remove(*statsPath)
		if err != nil {
			return err
		}
		return nil
	case <-ctx.Done():
		_ = n.send("STOPPING=1")
		select {
		case err := <-errc:
			_ = os.Remove(*statsPath)
			return err
		case <-time.After(10 * time.Second):
			return errors.New("server did not stop within 10s")
		}
	}
}

// waitReady polls the local port with a real DNS query until the engine answers.
func waitReady(ctx context.Context, addr, zone string, errc chan error, within time.Duration) error {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		select {
		case err := <-errc:
			if err == nil {
				err = errors.New("server stopped")
			}
			errc <- err // let the caller see it too
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if _, err := queryDNS(addr, zone, typeSOA, 300*time.Millisecond); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("no DNS answer on %s within %v", addr, within)
}

// watchdogLoop pings systemd only while the server really answers DNS, so a wedged
// process is restarted by systemd (WatchdogSec=).
func watchdogLoop(ctx context.Context, n *notifier, iv time.Duration, addr, zone string) {
	t := time.NewTicker(iv)
	defer t.Stop()
	timeout := iv / 2
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := queryDNS(addr, zone, typeSOA, timeout); err == nil {
				_ = n.send("WATCHDOG=1")
			}
		}
	}
}

func statsLoop(ctx context.Context, srv *vortexsrv.Server, path string) {
	write := func() {
		b, err := json.MarshalIndent(srv.Stats(), "", "  ")
		if err == nil {
			_ = writeFileAtomic(path, append(b, '\n'), 0o644)
		}
	}
	write()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			write()
		}
	}
}

func cmdStatus(args []string) error {
	fs := newFlags("status")
	cfgPath := fs.String("config", defaultConfig, "server config")
	statsPath := fs.String("stats", "", "stats file written by 'run'")
	asJSON := fs.Bool("json", false, "print raw JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := *statsPath
	if p == "" {
		for _, c := range []string{"/run/vortex-server/stats.json", defaultStatsPath(absConfig(*cfgPath))} {
			if _, err := os.Stat(c); err == nil {
				p = c
				break
			}
		}
	}
	if p == "" {
		return errors.New("no stats file found: is the server running? (systemctl status vortex-server)")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if *asJSON {
		_, err = stdout.Write(raw)
		return err
	}
	var st vortexsrv.Stats
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	age := time.Since(st.UpdatedAt).Round(time.Second)
	fmt.Fprintf(stdout, "Vortex server %s, up %s (updated %s ago)\n", st.Version, (time.Duration(st.UptimeSec) * time.Second).String(), age)
	fmt.Fprintf(stdout, "Domains: %s\n", strings.Join(st.Domains, ", "))
	v := st.Vortex
	fmt.Fprintf(stdout, "Active sessions: %d\n", v.Sessions)
	fmt.Fprintf(stdout, "Held polls: %d total, %d now (answered with data %d, empty %d)\n", v.Held, v.HeldNow, v.AnsweredData, v.AnsweredEmpty)
	fmt.Fprintf(stdout, "Resolver retries seen: %d, resolver groups: %d, hold limit hits: %d\n", v.Retries, v.Groups, v.Rejected)
	fmt.Fprintf(stdout, "Zone answers: %d\n", v.ZoneAnswers)
	if age > 45*time.Second {
		fmt.Fprintln(stdout, "warning: stats are stale; the server may not be running")
	}
	return nil
}
