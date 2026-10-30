package udpserver

import (
	"net"
	"testing"
	"time"
)

func TestEgressControlBlocksResolvedPrivate(t *testing.T) {
	old := allowPrivateEgress
	allowPrivateEgress = false
	defer func() { allowPrivateEgress = old }()
	for _, a := range []string{"127.0.0.1:80", "10.1.2.3:443", "169.254.169.254:80", "192.168.1.1:22", "[::1]:80", "100.64.0.1:80"} {
		if egressControl("tcp", a, nil) == nil {
			t.Fatalf("%s must be blocked", a)
		}
	}
	if err := egressControl("tcp", net.JoinHostPort("1.1.1.1", "443"), nil); err != nil {
		t.Fatalf("public address blocked: %v", err)
	}
}

func TestSessionLimiter(t *testing.T) {
	l := &sessionLimiter{b: map[uint8]*sessionBucket{}}
	now := time.Unix(0, 0)
	n := 0
	for i := 0; i < int(sessionBurst)+100; i++ {
		if l.allow(7, now) {
			n++
		}
	}
	if n != int(sessionBurst) {
		t.Fatalf("burst allowed %d", n)
	}
	if !l.allow(7, now.Add(10*time.Millisecond)) || !l.allow(8, now) {
		t.Fatal("refill and other sessions must pass")
	}
}
