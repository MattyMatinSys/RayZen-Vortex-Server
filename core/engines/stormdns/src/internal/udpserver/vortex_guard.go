package udpserver

// Vortex Server 2.0 abuse protection (patches/0003-vortex-server.patch): egress filter on
// resolved addresses and a per-session packet rate limit.

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

var errBlockedEgress = errors.New("egress to a private, loopback, link-local or metadata address is blocked")

// allowPrivateEgress is for the loopback lab only (VORTEX_ALLOW_PRIVATE_EGRESS=1).
var allowPrivateEgress = os.Getenv("VORTEX_ALLOW_PRIVATE_EGRESS") == "1"

// blockedEgressIP reports addresses a tunnel client must never reach through the server.
func blockedEgressIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return validateSOCKSTargetHost(ip.String()) != nil
}

// egressControl runs after name resolution, so hostnames that resolve to private ranges
// (DNS rebinding, /etc/hosts) are refused too, not only IP literals.
func egressControl(_, address string, _ syscall.RawConn) error {
	if allowPrivateEgress || os.Getenv("VORTEX_ALLOW_PRIVATE_EGRESS") == "1" {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || blockedEgressIP(net.ParseIP(host)) {
		return errBlockedEgress
	}
	return nil
}

func dialEgress(network, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, Control: egressControl}
	return d.Dial(network, address)
}

// Per-session token bucket: generous for a real tunnel, stops one session flooding the server.
const (
	sessionRatePerSec = 3000.0
	sessionBurst      = 6000.0
)

type sessionBucket struct {
	tokens float64
	last   time.Time
}

type sessionLimiter struct {
	mu sync.Mutex
	b  map[uint8]*sessionBucket
}

var limiter = &sessionLimiter{b: map[uint8]*sessionBucket{}}

func (l *sessionLimiter) allow(id uint8, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.b[id]
	if b == nil {
		b = &sessionBucket{tokens: sessionBurst, last: now}
		l.b[id] = b
	}
	b.tokens = min(sessionBurst, b.tokens+now.Sub(b.last).Seconds()*sessionRatePerSec)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
