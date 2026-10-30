package main

import (
	"context"
	"net"
	"stormdns-go/vortexsrv"
	"strconv"
	"testing"
	"time"
)

func runServer(t *testing.T, domains ...string) (string, string) {
	t.Helper()
	port := freeUDPPort(t)
	path := initServer(t, port, domains...)
	s, err := vortexsrv.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := vortexsrv.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := vortexsrv.ReadKey(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if m, err := queryDNS(addr, domains[0], typeSOA, 300*time.Millisecond); err == nil && m.Authoritative {
			return addr, key
		}
	}
	t.Fatal("server did not start")
	return "", ""
}
