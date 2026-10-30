package vortexsrv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	dnsparser "stormdns-go/internal/dnsparser"
	"stormdns-go/internal/enums"
	"stormdns-go/internal/security"
	"stormdns-go/internal/vpnproto"
)

// ProbeSession sends a compatible SESSION_INIT through a DNS endpoint and checks
// its response. It releases the temporary session with a best-effort close.
// The legacy response itself is not cryptographically authenticated.
func ProbeSession(ctx context.Context, addr, domain string, method int, key string, up, down int) error {
	if up < 10 || up > 65535 || down < 10 || down > 65535 {
		return fmt.Errorf("invalid MTU for session probe")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	codec, err := security.NewCodec(method, key)
	if err != nil {
		return err
	}
	payload := make([]byte, 10)
	binary.BigEndian.PutUint16(payload[2:4], uint16(up))
	binary.BigEndian.PutUint16(payload[4:6], uint16(down))
	if _, err := rand.Read(payload[6:10]); err != nil {
		return fmt.Errorf("session probe nonce: %w", err)
	}
	build := func(opts vpnproto.BuildOptions) ([]byte, error) {
		encoded, err := vpnproto.BuildEncoded(opts, codec)
		if err != nil {
			return nil, err
		}
		return dnsparser.BuildTunnelTXTQuestionPacket(domain, []byte(encoded), enums.DNS_RECORD_TYPE_TXT, 1232)
	}
	query, err := build(vpnproto.BuildOptions{PacketType: enums.PACKET_SESSION_INIT, Payload: payload})
	if err != nil {
		return fmt.Errorf("build session probe: %w", err)
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", addr)
	if err != nil {
		return fmt.Errorf("open session probe: %w", err)
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	if _, err = c.Write(query); err != nil {
		return fmt.Errorf("send session probe: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return fmt.Errorf("session probe received no response: %w", err)
	}
	if n < 12 || !bytes.Equal(buf[:2], query[:2]) || buf[2]&0x80 == 0 {
		return fmt.Errorf("session probe received an unrelated DNS response")
	}
	packet, err := dnsparser.ExtractVPNResponse(buf[:n], false)
	if err != nil {
		return fmt.Errorf("session probe response: %w", err)
	}
	if packet.PacketType == enums.PACKET_SESSION_BUSY && len(packet.Payload) >= 4 && bytes.Equal(packet.Payload[:4], payload[6:10]) {
		return fmt.Errorf("server session table is full")
	}
	if packet.PacketType != enums.PACKET_SESSION_ACCEPT || len(packet.Payload) < 7 || packet.Payload[0] == 0 || !bytes.Equal(packet.Payload[3:7], payload[6:10]) {
		return fmt.Errorf("server did not accept the session")
	}
	closeQuery, err := build(vpnproto.BuildOptions{SessionID: packet.Payload[0], SessionCookie: packet.Payload[1], PacketType: enums.PACKET_SESSION_CLOSE})
	if err == nil {
		_, _ = c.Write(closeQuery)
	}
	return nil
}
