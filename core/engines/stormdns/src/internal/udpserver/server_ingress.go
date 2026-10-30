// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"fmt"
	"time"

	DnsParser "stormdns-go/internal/dnsparser"
	domainMatcher "stormdns-go/internal/domainmatcher"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

func (s *Server) handlePacket(packet []byte) []byte {
	return s.handlePacketFrom(packet, nil)
}

// handlePacketFrom: rc (Vortex, 0003) lets a post-session answer be parked and written later.
func (s *Server) handlePacketFrom(packet []byte, rc *heldTarget) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return s.buildNoDataResponseLogged(packet, "request-parse-failed")
	}

	if !parsed.HasQuestion {
		return s.buildNoDataResponseLogged(packet, "request-has-no-question")
	}

	decision := s.domainMatcher.Match(parsed)
	if decision.Action == domainMatcher.ActionProcess {
		response := s.handleTunnelCandidate(packet, parsed, decision, rc)
		if response != nil {
			return response
		}

		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-process-failed")
	}

	if decision.Action == domainMatcher.ActionNoData {
		if zr := s.zoneResponse(packet, parsed, decision); zr != nil {
			return zr
		}
	}

	if decision.Action == domainMatcher.ActionFormatError || decision.Action == domainMatcher.ActionNoData {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
	}

	return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision, rc *heldTarget) []byte {
	vpnPacket, err := VpnProto.ParseInflatedFromLabels(decision.Labels, s.codec)
	if err != nil {
		if errors.Is(err, VpnProto.ErrInvalidFragmentInfo) {
			s.fragmentInvalidHeader.Add(1)
		}
		if zr := s.zoneResponse(packet, parsed, decision); zr != nil {
			return zr
		}
		return s.buildNoDataResponseLiteLogged(packet, parsed, "vpn-proto-parse-failed")
	}

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, time.Now())
		return s.buildNoDataResponseLiteLogged(packet, parsed, "session-close-notice")
	}

	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
		if !validation.ok {
			return validation.response
		}

		if !limiter.allow(validation.record.ID, time.Now()) {
			return s.buildNoDataResponseLiteLogged(packet, parsed, "session-rate-limited")
		}

		if !s.handlePostSessionPacket(vpnPacket, validation.record) {
			return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("post-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
		}

		if resp, ok := s.serveOrHold(vpnPacket.PacketType, packet, decision.RequestName, validation.record, rc); ok {
			return resp
		}
		return s.serveQueuedOrPong(packet, decision.RequestName, validation.record, time.Now())
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("pre-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
	}
}
