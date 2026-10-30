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
	for _, mode := range []byte{mtuProbeModeRaw, mtuProbeModeBase64} {
		t.Run(sessionResponseModeName(mode), func(t *testing.T) { testConcurrentSessionInitRetries(t, mode) })
	}
}

func testConcurrentSessionInitRetries(t *testing.T, mode byte) {
	s := New(config.ServerConfig{}, nil, nil)
	question, err := dnsparser.BuildTXTQuestionPacket("x.t.example.com", enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, sessionInitDataSize)
	payload[0] = mode
	binary.BigEndian.PutUint16(payload[2:4], 100)
	binary.BigEndian.PutUint16(payload[4:6], 500)
	copy(payload[6:], []byte{1, 2, 3, 4})
	pkt := vpnproto.Packet{PacketType: enums.PACKET_SESSION_INIT, Payload: payload}
	decision := domainmatcher.Decision{RequestName: "x.t.example.com"}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan sessionInitResult, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			response := s.handleSessionInitRequest(question, decision, pkt)
			packet, err := dnsparser.ExtractVPNResponse(response, mode == mtuProbeModeBase64)
			results <- sessionInitResult{packet: packet, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var first []byte
	for result := range results {
		if result.err != nil || result.packet.PacketType != enums.PACKET_SESSION_ACCEPT || len(result.packet.Payload) != sessionAcceptSize {
			t.Fatalf("SESSION_INIT retry failed: %v packet=%+v", result.err, result.packet)
		}
		if first == nil {
			first = append([]byte(nil), result.packet.Payload...)
		}
		if string(first) != string(result.packet.Payload) {
			t.Fatal("duplicate SESSION_INIT allocated a different session")
		}
	}
	if first[0] == 0 || string(first[3:]) != string(payload[6:]) || s.sessions.activeCount != 1 {
		t.Fatalf("invalid acceptance or retry leaked sessions: %x active=%d", first, s.sessions.activeCount)
	}
}

type sessionInitResult struct {
	packet vpnproto.Packet
	err    error
}
