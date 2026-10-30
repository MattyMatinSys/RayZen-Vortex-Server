// RayZen Vortex server tests (patches/0003-vortex-server.patch, new file).

package udpserver

import (
        "encoding/binary"
        "net"
        "strings"
        "sync"
        "testing"
        "time"

        DnsParser "stormdns-go/internal/dnsparser"
        domainMatcher "stormdns-go/internal/domainmatcher"
        Enums "stormdns-go/internal/enums"
        "stormdns-go/internal/mlq"
        "stormdns-go/internal/security"
        VpnProto "stormdns-go/internal/vpnproto"
)

func vxQuery(name string, qtype uint16) []byte {
        b := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
        for _, l := range strings.Split(name, ".") {
                b = append(b, byte(len(l)))
                b = append(b, l...)
        }
        return append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

func mustUDPAddr(s string) *net.UDPAddr {
        a, err := net.ResolveUDPAddr("udp", s)
        if err != nil {
                panic(err)
        }
        return a
}

type vxSink struct {
        mu  sync.Mutex
        got [][]byte
        ch  chan struct{}
}

func newSink() *vxSink { return &vxSink{ch: make(chan struct{}, 16)} }

func (k *vxSink) target(ip string) *heldTarget {
        t := &heldTarget{write: func(b []byte) {
                k.mu.Lock()
                k.got = append(k.got, append([]byte(nil), b...))
                k.mu.Unlock()
                k.ch <- struct{}{}
        }}
        t.addr = mustUDPAddr(ip)
        return t
}

func (k *vxSink) wait(t *testing.T, within time.Duration) []byte {
        t.Helper()
        select {
        case <-k.ch:
        case <-time.After(within):
                t.Fatalf("no answer within %v", within)
        }
        k.mu.Lock()
        defer k.mu.Unlock()
        return k.got[len(k.got)-1]
}

func (k *vxSink) none(t *testing.T, within time.Duration) {
        t.Helper()
        select {
        case <-k.ch:
                t.Fatalf("unexpected answer")
        case <-time.After(within):
        }
}

func newVortexTestServer(t *testing.T, o VortexOptions) (*Server, *sessionRecord) {
        t.Helper()
        s := &Server{sessions: newSessionStore(8, 32)}
        r := &sessionRecord{
                ID:               3,
                Cookie:           9,
                DownloadMTU:      512,
                DownloadMTUBytes: 512,
                Streams:          make(map[uint16]*Stream_server),
                ActiveStreams:    make([]uint16, 0, 4),
                RecentlyClosed:   make(map[uint16]recentlyClosedStreamRecord, 4),
                OrphanQueue:      mlq.New[VpnProto.Packet](8),
                txSignal:         &holdSignal{},
        }
        r.ensureStream0(nil)
        s.sessions.byID[r.ID] = r
        s.EnableVortex(o)
        t.Cleanup(s.stopVortex)
        return s, r
}

func packetType(t *testing.T, resp []byte) uint8 {
        t.Helper()
        p, err := DnsParser.ExtractVPNResponse(resp, false)
        if err != nil {
                t.Fatalf("not a tunnel answer: %v", err)
        }
        return p.PacketType
}

func TestHoldAnswersAsSoonAsDataIsQueued(t *testing.T) {
        s, r := newVortexTestServer(t, VortexOptions{HoldMax: 2 * time.Second, HoldInitial: 2 * time.Second})
        k := newSink()
        view := r.runtimeView()
        q := vxQuery("aaaa.t.example.com", Enums.DNS_RECORD_TYPE_TXT)
        resp, ok := s.serveOrHold(Enums.PACKET_PING, q, "aaaa.t.example.com", &view, k.target("10.1.2.3:53"))
        if !ok || len(resp) != 0 {
                t.Fatalf("expected the query to be parked, got ok=%v len=%d", ok, len(resp))
        }
        start := time.Now()
        time.Sleep(30 * time.Millisecond)
        r.enqueueOrphanReset(Enums.PACKET_STREAM_RST, 5, 0)
        got := k.wait(t, time.Second)
        if packetType(t, got) != Enums.PACKET_STREAM_RST {
                t.Fatalf("parked answer should carry the queued packet")
        }
        if el := time.Since(start); el > 500*time.Millisecond {
                t.Fatalf("parked answer left after %v, want right after the enqueue", el)
        }
        if st := s.VortexStats(); st.AnsweredData != 1 || st.Held != 1 || st.HeldNow != 0 {
                t.Fatalf("stats %+v", st)
        }
}

func TestHoldExpiresWithPongAndGrowsHold(t *testing.T) {
        s, r := newVortexTestServer(t, VortexOptions{HoldMax: 200 * time.Millisecond, HoldInitial: 60 * time.Millisecond, HoldStep: 20 * time.Millisecond})
        k := newSink()
        view := r.runtimeView()
        start := time.Now()
        if _, ok := s.serveOrHold(Enums.PACKET_PING, vxQuery("bbbb.t.example.com", 16), "bbbb.t.example.com", &view, k.target("10.9.9.9:53")); !ok {
                t.Fatal("expected park")
        }
        got := k.wait(t, time.Second)
        if packetType(t, got) != Enums.PACKET_PONG {
                t.Fatal("expired hold must answer PONG")
        }
        if el := time.Since(start); el < 50*time.Millisecond {
                t.Fatalf("answered after %v, before the hold", el)
        }
        time.Sleep(10 * time.Millisecond)
        if d := s.hold.holdFor(resolverGroup(mustUDPAddr("10.9.9.1:53"))); d != 80*time.Millisecond {
                t.Fatalf("clean hold should grow by one step, got %v", d)
        }
}

func TestResolverRetryHalvesHoldAndAnswersNow(t *testing.T) {
        s, r := newVortexTestServer(t, VortexOptions{HoldMax: time.Second, HoldInitial: 800 * time.Millisecond, HoldStep: 50 * time.Millisecond})
        k := newSink()
        view := r.runtimeView()
        name := "cccc.t.example.com"
        if _, ok := s.serveOrHold(Enums.PACKET_PING, vxQuery(name, 16), name, &view, k.target("192.0.2.10:53")); !ok {
                t.Fatal("expected park")
        }
        // Same name (case randomised by 0x20) from a neighbour address of the same resolver farm.
        if resp, ok := s.serveOrHold(Enums.PACKET_PING, vxQuery(name, 16), "CcCc.T.example.com", &view, k.target("192.0.2.77:53")); ok || resp != nil {
                t.Fatalf("a resolver retry must be answered immediately by the caller")
        }
        k.none(t, 150*time.Millisecond) // the abandoned copy is never answered
        if st := s.VortexStats(); st.Retries != 1 || st.HeldNow != 0 {
                t.Fatalf("stats %+v", st)
        }
        if d := s.hold.holdFor("192.0.2.0"); d != 400*time.Millisecond {
                t.Fatalf("hold after retry = %v, want halved 400ms", d)
        }
        // A different resolver group sending the same bytes (client duplication) is not a retry.
        if _, ok := s.serveOrHold(Enums.PACKET_PING, vxQuery(name, 16), name, &view, k.target("198.51.100.1:53")); !ok {
                t.Fatal("other resolver group should be parked")
        }
        if _, ok := s.serveOrHold(Enums.PACKET_PING, vxQuery(name, 16), name, &view, k.target("203.0.113.1:53")); !ok {
                t.Fatal("duplicate via a third group should be parked too")
        }
}

func TestHoldBoundsAndDisabledGroups(t *testing.T) {
        s, r := newVortexTestServer(t, VortexOptions{HoldMax: time.Second, HoldMaxPerSession: 1, HoldStep: 600 * time.Millisecond})
        k := newSink()
        view := r.runtimeView()
        // Queued data is served at once, never parked.
        r.enqueueOrphanReset(Enums.PACKET_STREAM_RST, 9, 0)
        resp, ok := s.serveOrHold(Enums.PACKET_PING, vxQuery("ffff.t.example.com", 16), "ffff.t.example.com", &view, k.target("10.0.0.2:53"))
        if !ok || len(resp) == 0 || packetType(t, resp) != Enums.PACKET_STREAM_RST {
                t.Fatal("queued data must be answered immediately")
        }
        if _, ok := s.serveOrHold(Enums.PACKET_PING, vxQuery("dddd.t.example.com", 16), "dddd.t.example.com", &view, k.target("10.0.0.1:53")); !ok {
                t.Fatal("first query should park")
        }
        if _, ok := s.serveOrHold(Enums.PACKET_PING, vxQuery("eeee.t.example.com", 16), "eeee.t.example.com", &view, k.target("10.0.0.1:53")); ok {
                t.Fatal("per-session bound must answer the second query now")
        }
        if st := s.VortexStats(); st.Rejected != 1 {
                t.Fatalf("stats %+v", st)
        }
        // A group whose hold dropped to zero answers immediately.
        s.hold.mu.Lock()
        s.hold.shrinkLocked("10.7.7.0", time.Now())
        s.hold.mu.Unlock()
        if d := s.hold.holdFor("10.7.7.0"); d != 0 {
                t.Fatalf("hold %v, want 0 after shrinking below one step", d)
        }
}

func TestOnlyPingsAreParked(t *testing.T) {
        s, r := newVortexTestServer(t, VortexOptions{HoldMax: time.Second, HoldInitial: time.Second})
        k := newSink()
        view := r.runtimeView()
        for _, pt := range []uint8{Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_SYN} {
                if resp, ok := s.serveOrHold(pt, vxQuery("gggg.t.example.com", 16), "gggg.t.example.com", &view, k.target("10.3.3.3:53")); ok || resp != nil {
                        t.Fatalf("packet type %d must be answered immediately, not parked", pt)
                }
        }
        if st := s.VortexStats(); st.Held != 0 {
                t.Fatalf("stats %+v", st)
        }
}


func TestZoneAnswersLookAuthoritative(t *testing.T) {
        codec, err := security.NewCodec(5, "0123456789abcdef0123456789abcdef")
        if err != nil {
                t.Fatal(err)
        }
        s := &Server{domainMatcher: domainMatcher.New([]string{"t.example.com"}, 3), codec: codec}
        s.EnableVortex(VortexOptions{Zone: []DnsParser.ZoneInfo{{
                Zone: "t.example.com", NSHost: "ns.example.com", Hostmaster: "hostmaster.example.com", Serial: 2026102301, TTL: 3600, NegTTL: 60,
        }}})
        DnsParser.SetAuthoritativeResponses(true)
        defer DnsParser.SetAuthoritativeResponses(false)

        check := func(name string, qtype uint16, rcode uint16, an, ns uint16, aa bool) []byte {
                t.Helper()
                resp := s.handlePacket(vxQuery(name, qtype))
                if len(resp) < 12 {
                        t.Fatalf("%s: no answer", name)
                }
                flags := binary.BigEndian.Uint16(resp[2:4])
                if got := flags & 0x000F; got != rcode {
                        t.Fatalf("%s: rcode %d want %d", name, got, rcode)
                }
                if (flags&(1<<10) != 0) != aa {
                        t.Fatalf("%s: AA=%v want %v", name, flags&(1<<10) != 0, aa)
                }
                if flags&(1<<7) != 0 {
                        t.Fatalf("%s: RA must be clear on an authoritative server", name)
                }
                if gotAN, gotNS := binary.BigEndian.Uint16(resp[6:8]), binary.BigEndian.Uint16(resp[8:10]); gotAN != an || gotNS != ns {
                        t.Fatalf("%s: AN=%d NS=%d want %d/%d", name, gotAN, gotNS, an, ns)
                }
                if _, err := DnsParser.ParsePacket(resp); err != nil {
                        t.Fatalf("%s: answer does not parse: %v", name, err)
                }
                return resp
        }
        soa := check("t.example.com", Enums.DNS_RECORD_TYPE_SOA, 0, 1, 0, true)
        if p, _ := DnsParser.ParsePacket(soa); p.Answers[0].Type != Enums.DNS_RECORD_TYPE_SOA {
                t.Fatal("apex SOA answer missing")
        }
        check("t.example.com", Enums.DNS_RECORD_TYPE_NS, 0, 1, 0, true)
        check("t.example.com", Enums.DNS_RECORD_TYPE_A, 0, 0, 1, true)
        // QNAME-minimised intermediate names and junk under the zone: NODATA + SOA, never NXDOMAIN.
        check("x.t.example.com", Enums.DNS_RECORD_TYPE_A, 0, 0, 1, true)
        check("zzzzzzzzzzzzzzzz.t.example.com", Enums.DNS_RECORD_TYPE_TXT, 0, 0, 1, true)
        check("www.google.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSR_CODE_REFUSED, 0, 0, false)
        if s.VortexStats().ZoneAnswers != 6 {
                t.Fatalf("zone answers %d", s.VortexStats().ZoneAnswers)
        }
}

func TestZoneAnswersOffKeepsUpstreamBehaviour(t *testing.T) {
        s := &Server{domainMatcher: domainMatcher.New([]string{"t.example.com"}, 3)}
        resp := s.handlePacket(vxQuery("www.google.com", Enums.DNS_RECORD_TYPE_A))
        if flags := binary.BigEndian.Uint16(resp[2:4]); flags&0x000F != 0 || flags&(1<<7) == 0 {
                t.Fatalf("upstream NODATA (RA set) expected, flags=%04x", flags)
        }
}
