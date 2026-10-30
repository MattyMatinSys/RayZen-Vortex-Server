package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"stormdns-go/vortexsrv"
)

const (
	typeSOA = dnsmessage.TypeSOA
	typeNS  = dnsmessage.TypeNS
	typeA   = dnsmessage.TypeA
)

// publicResolvers are used for delegation checks and the --public self test.
var publicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// ---- minimal DNS client (no dig / system resolver needed) ----

func queryDNS(addr, name string, t dnsmessage.Type, timeout time.Duration) (*dnsmessage.Message, error) {
	return queryDNSRD(addr, name, t, timeout, true)
}

func queryDNSRD(addr, name string, t dnsmessage.Type, timeout time.Duration, rd bool) (*dnsmessage.Message, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qn, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: rd})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: qn, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	pkt, err := b.Finish()
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		var m dnsmessage.Message
		if err := m.Unpack(buf[:n]); err != nil {
			continue
		}
		if m.ID != id || !m.Response {
			continue
		}
		return &m, nil
	}
}

func nameStr(n dnsmessage.Name) string { return strings.TrimSuffix(strings.ToLower(n.String()), ".") }

// lookupA resolves a host to IPv4 addresses through a public resolver.
func lookupA(host string) []string {
	for _, r := range publicResolvers[:2] {
		m, err := queryDNS(r, host, typeA, 3*time.Second)
		if err != nil {
			continue
		}
		var out []string
		for _, a := range m.Answers {
			if v, ok := a.Body.(*dnsmessage.AResource); ok {
				out = append(out, net.IP(v.A[:]).String())
			}
		}
		if len(out) > 0 || m.RCode == dnsmessage.RCodeNameError {
			return out
		}
	}
	return nil
}

func lookupNS(name string) []string {
	for _, r := range publicResolvers[:2] {
		m, err := queryDNS(r, name, typeNS, 3*time.Second)
		if err != nil {
			continue
		}
		var out []string
		for _, a := range m.Answers {
			if v, ok := a.Body.(*dnsmessage.NSResource); ok {
				out = append(out, nameStr(v.NS))
			}
		}
		return out
	}
	return nil
}

// parentServers finds the authoritative servers of the closest enclosing zone above d.
func parentServers(d string) (zone string, ips []string) {
	labels := strings.Split(d, ".")
	for i := 1; i < len(labels); i++ {
		z := strings.Join(labels[i:], ".")
		ns := lookupNS(z)
		if len(ns) == 0 {
			continue
		}
		for _, h := range ns {
			ips = append(ips, lookupA(h)...)
			if len(ips) >= 2 {
				break
			}
		}
		if len(ips) > 0 {
			return z, ips
		}
	}
	return "", nil
}

type delegation struct {
	parentZone string
	nsHosts    []string
	nsIPs      map[string][]string
}

// findDelegation asks the parent zone's own servers (no recursion) which name servers
// the tunnel domain is delegated to.
func findDelegation(d string) (delegation, error) {
	del := delegation{nsIPs: map[string][]string{}}
	zone, ips := parentServers(d)
	if zone == "" {
		return del, fmt.Errorf("could not find the name servers of any parent zone of %s", d)
	}
	del.parentZone = zone
	var m *dnsmessage.Message
	var err error
	for _, ip := range ips {
		if m, err = queryDNSRD(net.JoinHostPort(ip, "53"), d, typeNS, 3*time.Second, false); err == nil {
			break
		}
	}
	if m == nil {
		return del, fmt.Errorf("parent zone %s did not answer: %v", zone, err)
	}
	glue := map[string][]string{}
	for _, a := range m.Additionals {
		if v, ok := a.Body.(*dnsmessage.AResource); ok {
			h := nameStr(a.Header.Name)
			glue[h] = append(glue[h], net.IP(v.A[:]).String())
		}
	}
	for _, sec := range [][]dnsmessage.Resource{m.Authorities, m.Answers} {
		for _, a := range sec {
			if v, ok := a.Body.(*dnsmessage.NSResource); ok && nameStr(a.Header.Name) == d {
				del.nsHosts = append(del.nsHosts, nameStr(v.NS))
			}
		}
	}
	for _, h := range del.nsHosts {
		if g := glue[h]; len(g) > 0 {
			del.nsIPs[h] = g
		} else {
			del.nsIPs[h] = lookupA(h)
		}
	}
	return del, nil
}

func detectPublicIP() string {
	c := &http.Client{Timeout: 5 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://ipv4.icanhazip.com"} {
		resp, err := c.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if ip := net.ParseIP(strings.TrimSpace(string(b))); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// zoneSOA asks a public resolver for the SOA of d; ok when the answer is the one this
// server publishes (proves: delegation works and this server is reachable on UDP/53).
func zoneSOA(resolver, d, wantNS string) (bool, string) {
	m, err := queryDNS(resolver, d, typeSOA, 4*time.Second)
	if err != nil {
		return false, "no answer (" + shortErr(err) + ")"
	}
	if m.RCode != dnsmessage.RCodeSuccess {
		return false, "answer " + strings.TrimPrefix(m.RCode.String(), "RCode")
	}
	for _, a := range m.Answers {
		if v, ok := a.Body.(*dnsmessage.SOAResource); ok && nameStr(a.Header.Name) == d {
			if got := nameStr(v.NS); got == wantNS {
				return true, "SOA from this server"
			} else {
				return false, "SOA names " + got + " (not this server)"
			}
		}
	}
	return false, "no SOA in the answer"
}

func shortErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return err.Error()
}

type checkResult struct {
	domain    string
	delegated bool // parent delegates to an NS whose address is this server
	reachable bool // a public resolver got this server's SOA
	nsHost    string
}

func cmdCheckDNS(args []string) error {
	fs := newFlags("check-dns")
	cfgPath := fs.String("config", defaultConfig, "server config")
	ip := fs.String("ip", "", "public IPv4 of this server (default: detect)")
	writeNS := fs.Bool("write-ns-host", false, "store the delegated name server host in the config (VORTEX_NS_HOST)")
	wait := fs.Duration("wait", 0, "keep re-checking for up to this long (e.g. 5m) until everything passes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := absConfig(*cfgPath)
	cfg, err := vortexsrv.LoadConfig(path)
	if err != nil {
		return err
	}
	st, err := vortexsrv.LoadSettings(path)
	if err != nil {
		return err
	}
	if *ip == "" {
		*ip = detectPublicIP()
	}
	if *ip == "" {
		fmt.Fprintln(stdout, "warning: could not detect the public IP; pass --ip")
	}
	deadline := time.Now().Add(*wait)
	for {
		results := make([]checkResult, 0, len(cfg.Domain))
		allOK := true
		for _, d := range cfg.Domain {
			r := checkDomain(strings.ToLower(strings.TrimSuffix(d, ".")), *ip, st)
			results = append(results, r)
			allOK = allOK && r.delegated && r.reachable
		}
		if *writeNS {
			storeNSHost(path, st, results)
		}
		if allOK {
			fmt.Fprintln(stdout, "DNS check passed.")
			return nil
		}
		if *wait <= 0 || time.Now().After(deadline) {
			return exitCode(3)
		}
		fmt.Fprintf(stdout, "re-checking in 15s (until %s)...\n\n", deadline.Format("15:04:05"))
		time.Sleep(15 * time.Second)
	}
}

func checkDomain(d, ip string, st vortexsrv.Settings) checkResult {
	r := checkResult{domain: d}
	fmt.Fprintf(stdout, "Domain %s\n", d)
	del, err := findDelegation(d)
	want := vortexsrv.ZoneFor(d, st, 0).NSHost
	switch {
	case err != nil:
		fmt.Fprintf(stdout, "  [!!] delegation: %v\n", err)
	case len(del.nsHosts) == 0:
		fmt.Fprintf(stdout, "  [!!] %s is not delegated yet (no NS record in zone %s)\n", d, del.parentZone)
	default:
		for _, h := range del.nsHosts {
			ips := del.nsIPs[h]
			mark := "[!!]"
			for _, a := range ips {
				if a == ip {
					mark, r.delegated = "[ok]", true
					if r.nsHost == "" {
						r.nsHost = h
					}
				}
			}
			addr := strings.Join(ips, ", ")
			if addr == "" {
				addr = "no A record"
			}
			fmt.Fprintf(stdout, "  %s NS %s -> %s\n", mark, h, addr)
		}
		if !r.delegated && ip != "" {
			fmt.Fprintf(stdout, "  [!!] none of these name servers points to this server (%s)\n", ip)
		}
	}
	// want is what the running server publishes (from the config it started with).
	okCount := 0
	for _, res := range publicResolvers {
		ok, why := zoneSOA(res, d, want)
		mark := "[!!]"
		if ok {
			mark = "[ok]"
			okCount++
		}
		fmt.Fprintf(stdout, "  %s via %s: %s\n", mark, strings.TrimSuffix(res, ":53"), why)
	}
	r.reachable = okCount > 0
	if !r.delegated {
		printRecords(d, ip, del.parentZone, st)
	}
	return r
}

func printRecords(d, ip, parentZone string, st vortexsrv.Settings) {
	ns := vortexsrv.ZoneFor(d, st, 0).NSHost
	if ip == "" {
		ip = "<this server's IPv4>"
	}
	zone := parentZone
	if zone == "" {
		zone = d[strings.IndexByte(d, '.')+1:]
	}
	fmt.Fprintf(stdout, "\n  Add these records at the DNS provider of %s:\n", zone)
	fmt.Fprintf(stdout, "    %-28s A    %s\n", ns+".", ip)
	fmt.Fprintf(stdout, "    %-28s NS   %s\n", d+".", ns+".")
	if ns != zone && !strings.HasSuffix(ns, "."+zone) {
		fmt.Fprintf(stdout, "  (The A record of %s belongs at the DNS provider of its own zone.)\n", ns)
	}
	fmt.Fprintln(stdout)
}

// storeNSHost records the real delegation host so SOA/NS answers match the parent zone.
func storeNSHost(path string, st vortexsrv.Settings, results []checkResult) {
	host := ""
	allMatch := len(results) > 0
	different := false
	for _, r := range results {
		if !r.delegated || r.nsHost == "" {
			return // Do not change every zone while any delegation is unknown.
		}
		if r.nsHost != vortexsrv.ZoneFor(r.domain, st, 0).NSHost {
			allMatch = false
		}
		if host == "" {
			host = r.nsHost
		} else if host != r.nsHost {
			different = true
		}
	}
	if host == "" || allMatch {
		return
	}
	if different {
		// A single global NS host cannot represent different delegations.
		fmt.Fprintln(stdout, "warning: domains use different nameserver hosts; VORTEX_NS_HOST was not changed")
		return
	}
	if host == st.NSHost {
		return
	}
	if st.NSHost == "" && len(results) > 0 && host == vortexsrv.ZoneFor(results[0].domain, st, 0).NSHost {
		return // the default already matches
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if err := writeFileAtomic(path, []byte(setTOMLKey(string(raw), "VORTEX_NS_HOST", tomlString(host))), 0o640); err == nil {
		fmt.Fprintf(stdout, "stored VORTEX_NS_HOST = %q (restart the server to publish it)\n", host)
	}
}

// ---- selfcheck: real tunnel handshake with the engine's own client probes ----

type prober interface {
	ProbeFixed(ctx context.Context, ip string, port, up, down int, timeout time.Duration) (bool, time.Duration)
	Discover(ctx context.Context, ip string, port int) (up, upChars, down int, rtt time.Duration, ok bool)
}

var newProber = func(domain, key string, method int) (prober, error) { return vortexsrv.NewProber(domain, key, method) }
var probeSession = vortexsrv.ProbeSession

func cmdSelfcheck(args []string) error {
	fs := newFlags("selfcheck")
	cfgPath := fs.String("config", defaultConfig, "server config")
	public := fs.Bool("public", false, "also test through public resolvers (needs working delegation)")
	publicOnly := fs.Bool("public-only", false, "only the public resolver test")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *publicOnly {
		*public = true
	}
	path := absConfig(*cfgPath)
	cfg, err := vortexsrv.LoadConfig(path)
	if err != nil {
		return err
	}
	key, err := vortexsrv.ReadKey(cfg)
	if err != nil {
		return err
	}
	host, portStr, _ := net.SplitHostPort(probeAddr(cfg.UDPHost, cfg.UDPPort))
	port, _ := strconv.Atoi(portStr)
	failed := false
	for _, d := range cfg.Domain {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		p, err := newProber(d, key, cfg.DataEncryptionMethod)
		if err != nil {
			return err
		}
		if !*publicOnly {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			up, _, down, rtt, ok := p.Discover(ctx, host, port)
			cancel()
			var sessionErr error
			if ok {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				sessionErr = probeSession(ctx, net.JoinHostPort(host, portStr), d, cfg.DataEncryptionMethod, key, up, down)
				cancel()
				ok = sessionErr == nil
			}
			if ok {
				fmt.Fprintf(stdout, "[ok] %s: tunnel handshake on this server works; session accepted (upload MTU %d, download MTU %d, %v)\n", d, up, down, rtt.Round(time.Millisecond))
			} else {
				failed = true
				if sessionErr != nil {
					fmt.Fprintf(stdout, "[!!] %s: MTU probes passed but session initialization failed: %v\n", d, sessionErr)
				} else {
					fmt.Fprintf(stdout, "[!!] %s: no tunnel MTU response on %s:%d (is vortex-server running? journalctl -u vortex-server)\n", d, host, port)
				}
			}
		}
		if *public {
			pass := 0
			for _, r := range publicResolvers {
				rip := strings.TrimSuffix(r, ":53")
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				ok, rtt := p.ProbeFixed(ctx, rip, 53, 100, 500, 4*time.Second)
				cancel()
				if ok {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					err := probeSession(ctx, r, d, cfg.DataEncryptionMethod, key, 100, 500)
					cancel()
					if err != nil {
						ok = false
						fmt.Fprintf(stdout, "[!!] %s: session through %s failed: %v\n", d, rip, err)
					}
				}
				if ok {
					pass++
					fmt.Fprintf(stdout, "[ok] %s: tunnel works through public resolver %s (%v)\n", d, rip, rtt.Round(time.Millisecond))
				} else {
					fmt.Fprintf(stdout, "[!!] %s: no tunnel through public resolver %s\n", d, rip)
				}
			}
			if pass == 0 {
				failed = true
			}
		}
	}
	if failed {
		return exitCode(4)
	}
	return nil
}
