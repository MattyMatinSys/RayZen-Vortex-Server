package udpserver

import (
	"encoding/binary"
	"sync"
	"testing"

	"stormdns-go/internal/config"
	dnsparser "stormdns-go/internal/dnsparser"
	"stormdns-go/internal/domainmatcher"
	"stormdns-go/internal/enums"
	"stormdns-go/internal/vpnproto"
)

// Retries of the same SESSION_INIT can reach different workers concurrently.
func TestConcurrentSessionInitRetries(t *testing.T) {
	s := New(config.ServerConfig{}, nil, nil)
	question, err := dnsparser.BuildTXTQuestionPacket("x.t.example.com", enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, sessionInitDataSize)
	binary.BigEndian.PutUint16(payload[2:4], 100)
	binary.BigEndian.PutUint16(payload[4:6], 500)
	copy(payload[6:], []byte{1, 2, 3, 4})
	pkt := vpnproto.Packet{PacketType: enums.PACKET_SESSION_INIT, Payload: payload}
	decision := domainmatcher.Decision{RequestName: "x.t.example.com"}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; s.handleSessionInitRequest(question, decision, pkt) }()
	}
	close(start)
	wg.Wait()
}
