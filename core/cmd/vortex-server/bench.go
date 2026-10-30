package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stormdns-go/vortexsrv"
)

// cmdBench: loopback throughput of the running server with real tunnel probes, per direction.
func cmdBench(args []string) error {
	fs := newFlags("bench")
	cfgPath := fs.String("config", defaultConfig, "server config")
	secs := fs.Int("seconds", 3, "seconds per direction")
	par := fs.Int("parallel", 8, "parallel probes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := vortexsrv.LoadConfig(absConfig(*cfgPath))
	if err != nil {
		return err
	}
	key, err := vortexsrv.ReadKey(cfg)
	if err != nil {
		return err
	}
	if len(cfg.Domain) == 0 {
		return fmt.Errorf("no domain configured")
	}
	host, portStr, _ := net.SplitHostPort(probeAddr(cfg.UDPHost, cfg.UDPPort))
	port, _ := strconv.Atoi(portStr)
	d := strings.ToLower(strings.TrimSuffix(cfg.Domain[0], "."))
	p, err := newProber(d, key, cfg.DataEncryptionMethod)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	up, _, down, _, ok := p.Discover(ctx, host, port)
	cancel()
	if !ok {
		fmt.Fprintf(stdout, "[!!] no tunnel handshake on %s:%d (is vortex-server running?)\n", host, port)
		return exitCode(4)
	}
	run := func(u, dn, count int) float64 {
		var bytes atomic.Int64
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*secs)*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		for i := 0; i < *par; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ctx.Err() == nil {
					if good, _ := p.ProbeFixed(ctx, host, port, u, dn, 2*time.Second); good {
						bytes.Add(int64(count))
					}
				}
			}()
		}
		wg.Wait()
		return float64(bytes.Load()) / 1024 / float64(*secs)
	}
	dl := run(min(up, 60), down, down)
	ul := run(up, 256, up)
	fmt.Fprintf(stdout, "MTU probe payload rates (not application throughput): %s on %s:%d (MTU up %d / down %d, %d parallel, %ds each)\n", d, host, port, up, down, *par, *secs)
	fmt.Fprintf(stdout, "  download: %.1f KiB/s\n  upload:   %.1f KiB/s\n", dl, ul)
	return nil
}
