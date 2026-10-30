package vortexsrv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strconv"
	"time"

	dnsparser "stormdns-go/internal/dnsparser"
	"stormdns-go/internal/enums"
	"stormdns-go/internal/security"
	"stormdns-go/internal/vpnproto"
)

// Prober is a small server diagnostic; it does not run a tunnel client.
type Prober struct {
	domain string
	codec  *security.Codec
}

func NewProber(domain, key string, method int) (*Prober, error) {
	codec, err := security.NewCodec(method, key)
	if err != nil {
		return nil, err
	}
	return &Prober{domain: domain, codec: codec}, nil
}

func (p *Prober) query(packetType uint8, payload []byte) ([]byte, error) {
	encoded, err := vpnproto.BuildEncoded(vpnproto.BuildOptions{SessionID: 255, PacketType: packetType, StreamID: 1, SequenceNum: 1, TotalFragments: 1, Payload: payload}, p.codec)
	if err != nil {
		return nil, err
	}
	return dnsparser.BuildTunnelTXTQuestionPacket(p.domain, []byte(encoded), enums.DNS_RECORD_TYPE_TXT, 4096)
}

func (p *Prober) mtuProbe(ctx context.Context, ip string, port, up, down int, upload bool) (bool, time.Duration) {
	if up < 10 || up > 512 || down < 30 || down > 4096 {
		return false, 0
	}
	payload := make([]byte, max(up, 7))
	if _, err := rand.Read(payload[1:5]); err != nil {
		return false, 0
	}
	typ, want := enums.PACKET_MTU_UP_REQ, enums.PACKET_MTU_UP_RES
	wantLen := 6
	if !upload {
		typ, want, wantLen = enums.PACKET_MTU_DOWN_REQ, enums.PACKET_MTU_DOWN_RES, down
		binary.BigEndian.PutUint16(payload[5:7], uint16(down))
	}
	query, err := p.query(uint8(typ), payload)
	if err != nil {
		return false, 0
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false, 0
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	start := time.Now()
	if _, err := c.Write(query); err != nil {
		return false, 0
	}
	buf := make([]byte, 8192)
	n, err := c.Read(buf)
	if err != nil || n < 12 || !bytes.Equal(buf[:2], query[:2]) || buf[2]&0x80 == 0 {
		return false, 0
	}
	packet, err := dnsparser.ExtractVPNResponse(buf[:n], false)
	if err != nil || packet.PacketType != uint8(want) || len(packet.Payload) != wantLen || !bytes.Equal(packet.Payload[:4], payload[1:5]) {
		return false, 0
	}
	expected := up
	if !upload {
		expected = down
	}
	if int(binary.BigEndian.Uint16(packet.Payload[4:6])) != expected {
		return false, 0
	}
	return true, time.Since(start)
}

func (p *Prober) ProbeFixed(ctx context.Context, ip string, port, up, down int, timeout time.Duration) (bool, time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, 2*timeout)
	defer cancel()
	if ok, r1 := p.mtuProbe(ctx, ip, port, up, down, true); ok {
		if ok, r2 := p.mtuProbe(ctx, ip, port, up, down, false); ok {
			return true, (r1 + r2) / 2
		}
	}
	return false, 0
}

func (p *Prober) Discover(ctx context.Context, ip string, port int) (up, upChars, down int, rtt time.Duration, ok bool) {
	// Find the largest upload payload that fits a DNS name before probing.
	high := 200
	for high >= 10 {
		if _, err := p.query(enums.PACKET_MTU_UP_REQ, make([]byte, high)); err == nil {
			break
		}
		high--
	}
	search := func(low, high int, probe func(int) (bool, time.Duration)) (int, time.Duration) {
		best := 0
		var bestRTT time.Duration
		for low <= high && ctx.Err() == nil {
			mid := (low + high) / 2
			pass, elapsed := probe(mid)
			if !pass && ctx.Err() == nil {
				pass, elapsed = probe(mid)
			}
			if pass {
				best, bestRTT, low = mid, elapsed, mid+1
			} else {
				high = mid - 1
			}
		}
		return best, bestRTT
	}
	up, urtt := search(10, high, func(n int) (bool, time.Duration) { return p.mtuProbe(ctx, ip, port, n, 30, true) })
	if up == 0 {
		return 0, 0, 0, 0, false
	}
	down, drtt := search(30, 4000, func(n int) (bool, time.Duration) { return p.mtuProbe(ctx, ip, port, up, n, false) })
	if down == 0 || ctx.Err() != nil {
		return 0, 0, 0, 0, false
	}
	return up, 0, down, (urtt + drtt) / 2, true
}
