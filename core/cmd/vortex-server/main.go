// Command vortex-server is the RayZen Vortex DNS-tunnel server: the StormDNS engine with
// the Vortex additions (response hold, authoritative zone answers) plus everything an
// operator needs on a VPS (config, key, link, DNS delegation check, self test, systemd).
//
//	vortex-server init      --config /etc/vortex-server/server.toml --domain t.example.com [--domain t2.example.net]
//	vortex-server run       --config ... [--stats /run/vortex-server/stats.json]
//	vortex-server link      --config ... [--name "My server"]
//	vortex-server keygen    --config ... [--rotate]
//	vortex-server domain    add|remove|list <domain> --config ...
//	vortex-server check-dns --config ... [--ip PUBLIC_IP] [--write-ns-host]
//	vortex-server selfcheck --config ... [--public]
//	vortex-server status    [--stats ...] [--json]
//	vortex-server bench     --config ... [--seconds 3] [--parallel 8]
//	vortex-server version
//
// All operator-facing output is English (decision D-30); the key is never logged.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const defaultConfig = "/etc/vortex-server/server.toml"

// stdout/stderr are swappable for tests.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

type command struct {
	name  string
	usage string
	run   func(args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"init", "create the server config and key", cmdInit},
		{"run", "run the server (systemd: Type=notify, watchdog aware)", cmdRun},
		{"link", "print the vortex:// link for the app (v1.4.0 or newer)", cmdLink},
		{"keygen", "create the key if missing (--rotate makes a new one)", cmdKeygen},
		{"domain", "add|remove|list tunnel domains", cmdDomain},
		{"check-dns", "check that the domain(s) are delegated to this server", cmdCheckDNS},
		{"selfcheck", "real tunnel handshake against this server (and via public resolvers with --public)", cmdSelfcheck},
		{"status", "show live counters of the running server", cmdStatus},
		{"bench", "loopback tunnel throughput test (download and upload)", cmdBench},
		{"version", "print the version", cmdVersion},
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "RayZen Vortex server %s\n\nUsage: vortex-server <command> [options]\n\nCommands:\n", version())
	for _, c := range commands {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.usage)
	}
	fmt.Fprintf(w, "\nRun 'vortex-server <command> -h' for the options of a command.\n")
}

func main() {
	os.Exit(dispatch(os.Args[1:]))
}

func dispatch(args []string) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	name := args[0]
	switch name {
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	case "-v", "--version":
		name = "version"
	}
	for _, c := range commands {
		if c.name == name {
			if err := c.run(args[1:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return 0
				}
				var ec exitCode
				if errors.As(err, &ec) {
					return int(ec) // the command already explained the failure
				}
				fmt.Fprintf(stderr, "vortex-server %s: %v\n", name, err)
				return 1
			}
			return 0
		}
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n", name)
	usage(stderr)
	return 2
}

// exitCode lets a command fail with a specific status without extra output.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("vortex-server "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// multiFlag collects a repeatable string flag (--domain a --domain b, or --domain a,b).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

// parseInterleaved parses flags that may appear after positional args.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func absConfig(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}
