// RayZen Vortex server additions (patches/0003-vortex-server.patch, new file).
//
//  1. Response hold ("long-poll"): when a post-session query finds nothing queued for its
//     session, the answer is parked (workers are never blocked) until data is queued for
//     that session or the hold deadline passes. Downstream data then leaves on the query
//     that is already waiting at the resolver instead of the client's next poll.
//  2. Adaptive hold per resolver group: a recursive resolver that gives up and re-sends the
//     same query while it is parked shows us its timeout; that group's hold is halved, and
//     it grows again slowly while holds expire cleanly (AIMD).
//  3. Zone answers: non-tunnel queries get answers a plain authoritative server would give.
//
// Wire format, crypto and session logic are unchanged. The supported client is RayZen
// Vortex-53 v1.4.0+ (its vortex:// v2 links and hold-aware ping tuning); older apps refuse
// the v2 link, so they are never pointed at this server by our installer.

package udpserver

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	DnsParser "stormdns-go/internal/dnsparser"
	domainMatcher "stormdns-go/internal/domainmatcher"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

// VortexOptions turns on the Vortex server behaviour. The zero value changes nothing.
type VortexOptions struct {
	HoldMax           time.Duration // 0 disables the response hold
	HoldInitial       time.Duration // first hold for a resolver group we have not seen
	HoldStep          time.Duration // additive increase after a clean hold
	HoldMaxPerSession int
	HoldMaxTotal      int
	// HoldAllTypes parks any post-session query that finds nothing queued (uploads, ACKs,
	// SYNs, PINGs), not only PINGs. The upload itself is always processed first.
	HoldAllTypes bool
	Zone         []DnsParser.ZoneInfo // authoritative zone answers (empty = upstream behaviour)
}

// VortexStats are monotonic counters for `vortex-server status` and the lab.
type VortexStats struct {
	Held          uint64 `json:"held"`
	AnsweredData  uint64 `json:"answeredWithData"`
	AnsweredEmpty uint64 `json:"answeredEmpty"`
	Retries       uint64 `json:"resolverRetries"`
	Rejected      uint64 `json:"holdRejected"`
	HeldNow       int    `json:"heldNow"`
	Groups        int    `json:"resolverGroups"`
	ZoneAnswers   uint64 `json:"zoneAnswers"`
	Sessions      int    `json:"activeSessions"`
}

// vortexState is embedded in Server (one-line upstream change in server.go).
type vortexState struct {
	hold        *holdManager
	zones       []DnsParser.ZoneInfo
	zoneAnswers atomic.Uint64
}

// heldSentinel tells dnsWorker that the answer will be written later.
var heldSentinel = []byte{}

// holdSignal is a broadcast "data was queued" signal for one session.
type holdSignal struct {
	mu sync.Mutex
	ch chan struct{}
}

func (h *holdSignal) waitCh() <-chan struct{} {
	h.mu.Lock()
	if h.ch == nil {
		h.ch = make(chan struct{})
	}
	c := h.ch
	h.mu.Unlock()
	return c
}

func (h *holdSignal) notify() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.ch != nil {
		close(h.ch)
		h.ch = nil
	}
	h.mu.Unlock()
}

type heldTarget struct {
	conn *net.UDPConn
	addr *net.UDPAddr
	// write is used instead of conn when set (tests, lab).
	write func([]byte)
}

func (t *heldTarget) send(b []byte) {
	if t == nil || len(b) == 0 {
		return
	}
	if t.write != nil {
		t.write(b)
		return
	}
	if t.conn != nil && t.addr != nil {
		_, _ = t.conn.WriteToUDP(b, t.addr)
	}
}

type heldRequest struct {
	question []byte
	name     string
	key      string
	group    string
	record   sessionRuntimeView
	target   *heldTarget
	signal   *holdSignal
	cancel   chan struct{}
}

type holdGroup struct {
	hold     time.Duration
	lastSeen time.Time
	shrunkAt time.Time
}

type holdManager struct {
	opts    VortexOptions
	mu      sync.Mutex
	waiting map[string]*heldRequest
	perSess map[uint8]int
	groups  map[string]*holdGroup
	done    chan struct{}
	once    sync.Once
	now     func() time.Time

	held, answeredData, answeredEmpty, retries, rejected, zoneAnswers atomic.Uint64
}

const (
	holdGroupCap      = 16384
	holdGroupIdle     = 15 * time.Minute
	holdReprobeAfter  = 2 * time.Minute
	defaultHoldPerSes = 64
	defaultHoldTotal  = 8192
)

func newHoldManager(o VortexOptions) *holdManager {
	if o.HoldInitial <= 0 || o.HoldInitial > o.HoldMax {
		o.HoldInitial = o.HoldMax / 2
	}
	if o.HoldStep <= 0 {
		o.HoldStep = 25 * time.Millisecond
	}
	if o.HoldMaxPerSession <= 0 {
		o.HoldMaxPerSession = defaultHoldPerSes
	}
	if o.HoldMaxTotal <= 0 {
		o.HoldMaxTotal = defaultHoldTotal
	}
	return &holdManager{
		opts:    o,
		waiting: make(map[string]*heldRequest, 256),
		perSess: make(map[uint8]int, 64),
		groups:  make(map[string]*holdGroup, 256),
		done:    make(chan struct{}),
		now:     time.Now,
	}
}

func (h *holdManager) stop() { h.once.Do(func() { close(h.done) }) }

// resolverGroup keys hold state by /24 (IPv4) or /48 (IPv6): big resolvers retry from
// neighbouring egress addresses.
func resolverGroup(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	if v4 := addr.IP.To4(); v4 != nil {
		return net.IPv4(v4[0], v4[1], v4[2], 0).String()
	}
	ip := addr.IP.To16()
	if ip == nil {
		return addr.IP.String()
	}
	m := make(net.IP, 16)
	copy(m, ip[:6])
	return m.String()
}

// holdFor returns the current hold for a resolver group (0 = answer now).
func (h *holdManager) holdFor(group string) time.Duration {
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	g := h.groups[group]
	if g == nil {
		if len(h.groups) >= holdGroupCap {
			h.pruneGroupsLocked(now)
		}
		g = &holdGroup{hold: h.opts.HoldInitial}
		h.groups[group] = g
	}
	g.lastSeen = now
	if g.hold <= 0 && now.Sub(g.shrunkAt) >= holdReprobeAfter {
		g.hold = h.opts.HoldStep
	}
	return g.hold
}

func (h *holdManager) pruneGroupsLocked(now time.Time) {
	for k, g := range h.groups {
		if now.Sub(g.lastSeen) > holdGroupIdle {
			delete(h.groups, k)
		}
	}
	if len(h.groups) >= holdGroupCap { // still full: drop arbitrary entries
		n := len(h.groups) / 4
		for k := range h.groups {
			if n <= 0 {
				break
			}
			delete(h.groups, k)
			n--
		}
	}
}

func (h *holdManager) noteClean(group string) {
	h.mu.Lock()
	if g := h.groups[group]; g != nil && g.hold > 0 {
		g.hold += h.opts.HoldStep
		if g.hold > h.opts.HoldMax {
			g.hold = h.opts.HoldMax
		}
	}
	h.mu.Unlock()
}

func (h *holdManager) shrinkLocked(group string, now time.Time) {
	g := h.groups[group]
	if g == nil {
		g = &holdGroup{lastSeen: now}
		h.groups[group] = g
	}
	g.hold /= 2
	if g.hold < h.opts.HoldStep {
		g.hold = 0
	}
	g.shrunkAt = now
}

// takeRetry: the same query name from the same resolver group is already parked, so the
// resolver timed out and re-sent it. The parked copy is dropped (nobody waits for it any
// more), the group's hold is halved, and the caller answers the new copy immediately.
func (h *holdManager) takeRetry(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.waiting[key]
	if r == nil {
		return false
	}
	h.removeLocked(r)
	close(r.cancel)
	h.shrinkLocked(r.group, h.now())
	h.retries.Add(1)
	return true
}

func (h *holdManager) register(r *heldRequest) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.waiting) >= h.opts.HoldMaxTotal || h.perSess[r.record.ID] >= h.opts.HoldMaxPerSession {
		h.rejected.Add(1)
		return false
	}
	if _, dup := h.waiting[r.key]; dup {
		return false
	}
	h.waiting[r.key] = r
	h.perSess[r.record.ID]++
	h.held.Add(1)
	return true
}

func (h *holdManager) removeLocked(r *heldRequest) {
	if cur, ok := h.waiting[r.key]; ok && cur == r {
		delete(h.waiting, r.key)
		if n := h.perSess[r.record.ID] - 1; n > 0 {
			h.perSess[r.record.ID] = n
		} else {
			delete(h.perSess, r.record.ID)
		}
	}
}

func (h *holdManager) finish(r *heldRequest) {
	h.mu.Lock()
	h.removeLocked(r)
	h.mu.Unlock()
}

// EnableVortex switches on the Vortex server behaviour. Call before Run.
func (s *Server) EnableVortex(o VortexOptions) {
	if o.HoldMax > 0 {
		s.hold = newHoldManager(o)
	}
	s.zones = nil
	for _, z := range o.Zone {
		z.Zone = strings.TrimSuffix(strings.ToLower(z.Zone), ".")
		if z.Zone != "" {
			s.zones = append(s.zones, z)
		}
	}
}

// VortexStats returns a snapshot of the Vortex counters.
func (s *Server) VortexStats() VortexStats {
	st := VortexStats{ZoneAnswers: s.zoneAnswers.Load()}
	if s.sessions != nil {
		s.sessions.mu.RLock()
		st.Sessions = int(s.sessions.activeCount)
		s.sessions.mu.RUnlock()
	}
	h := s.hold
	if h == nil {
		return st
	}
	st.Held, st.AnsweredData, st.AnsweredEmpty = h.held.Load(), h.answeredData.Load(), h.answeredEmpty.Load()
	st.Retries, st.Rejected = h.retries.Load(), h.rejected.Load()
	h.mu.Lock()
	st.HeldNow, st.Groups = len(h.waiting), len(h.groups)
	h.mu.Unlock()
	return st
}

func (s *Server) stopVortex() {
	if s.hold != nil {
		s.hold.stop()
	}
}

// serveOrHold answers a post-session query: queued data now, or park it. By default only
// PINGs are parked; with HoldAllTypes every post-session query is (its upload was already
// processed). It returns (nil, false) when the caller should answer immediately with the
// upstream path.
func (s *Server) serveOrHold(packetType uint8, question []byte, requestName string, rec *sessionRuntimeView, rc *heldTarget) ([]byte, bool) {
	h := s.hold
	if h == nil || rc == nil || rec == nil || (packetType != Enums.PACKET_PING && !h.opts.HoldAllTypes) {
		return nil, false
	}
	group := resolverGroup(rc.addr)
	key := group + "|" + strings.ToLower(requestName)
	retry := h.takeRetry(key)
	if pkt, ok := s.dequeueSessionResponse(rec.ID, time.Now()); ok {
		return s.buildSessionVPNResponse(question, requestName, rec, *pkt), true
	}
	if retry {
		return nil, false
	}
	d := h.holdFor(group)
	if d <= 0 {
		return nil, false
	}
	record, ok := s.sessions.Get(rec.ID)
	if !ok || record == nil || record.txSignal == nil {
		return nil, false
	}
	r := &heldRequest{
		question: append([]byte(nil), question...),
		name:     requestName,
		key:      key,
		group:    group,
		record:   *rec,
		target:   rc,
		signal:   record.txSignal,
		cancel:   make(chan struct{}),
	}
	if !h.register(r) {
		return nil, false
	}
	go s.runHeld(r, d)
	return heldSentinel, true
}

func (s *Server) runHeld(r *heldRequest, d time.Duration) {
	h := s.hold
	timer := time.NewTimer(d)
	defer timer.Stop()
	defer h.finish(r)
	for {
		ch := r.signal.waitCh()
		if pkt, ok := s.dequeueSessionResponse(r.record.ID, time.Now()); ok {
			h.answeredData.Add(1)
			r.target.send(s.buildSessionVPNResponse(r.question, r.name, &r.record, *pkt))
			return
		}
		select {
		case <-ch:
		case <-timer.C:
			h.answeredEmpty.Add(1)
			h.noteClean(r.group)
			r.target.send(s.buildPongResponse(r.question, r.name, &r.record))
			return
		case <-r.cancel:
			return
		case <-h.done:
			return
		}
	}
}

func (s *Server) buildPongResponse(question []byte, requestName string, rec *sessionRuntimeView) []byte {
	payload := s.nextPongPayload()
	return s.buildSessionVPNResponse(question, requestName, rec, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload[:],
	})
}

// zoneResponse answers non-tunnel queries like an authoritative server for our zones.
// It returns nil when zone answers are off (the caller keeps the upstream NODATA).
func (s *Server) zoneResponse(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	if len(s.zones) == 0 || !parsed.HasQuestion {
		return nil
	}
	name := decision.RequestName
	if name == "" {
		name = strings.TrimSuffix(strings.ToLower(parsed.FirstQuestion.Name), ".")
	}
	var zone *DnsParser.ZoneInfo
	for i := range s.zones {
		z := &s.zones[i]
		if name == z.Zone || strings.HasSuffix(name, "."+z.Zone) {
			if zone == nil || len(z.Zone) > len(zone.Zone) {
				zone = z
			}
		}
	}
	var resp []byte
	var err error
	if zone == nil {
		resp, err = DnsParser.BuildRefusedNonAuthoritative(packet, parsed)
	} else {
		resp, err = DnsParser.BuildZoneResponse(packet, parsed, *zone, name, parsed.FirstQuestion.Type)
	}
	if err != nil {
		return nil
	}
	s.zoneAnswers.Add(1)
	return resp
}

// RunContext is Run with a hook to stop parked answers on shutdown.
func (s *Server) RunContext(ctx context.Context) error {
	defer s.stopVortex()
	return s.Run(ctx)
}

// safeHandlePacketFrom is safeHandlePacket plus the reply target needed to park answers.
func (s *Server) safeHandlePacketFrom(packet []byte, conn *net.UDPConn, addr *net.UDPAddr) (response []byte) {
	if s.hold == nil {
		return s.safeHandlePacket(packet)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if s.log != nil {
				s.log.Errorf("\U0001F4A5 <red>Packet Handler Panic Recovered, <yellow>%v</yellow></red>", recovered)
			}
			response = nil
		}
	}()
	return s.handlePacketFrom(packet, &heldTarget{conn: conn, addr: addr})
}
