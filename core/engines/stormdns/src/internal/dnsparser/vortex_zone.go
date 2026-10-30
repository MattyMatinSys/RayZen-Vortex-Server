// RayZen Vortex server: authoritative-looking answers for non-tunnel queries.
// Added by patches/0003-vortex-server.patch (new file). Client code never calls it.

package dnsparser

import (
	"encoding/binary"
	"errors"
	"strings"
	"sync/atomic"

	Enums "stormdns-go/internal/enums"
)

var authoritativeMode atomic.Bool

// SetAuthoritativeResponses makes every response built by this package carry the
// flags of an authoritative name server (AA=1, RA=0). Only the Vortex server binary
// turns this on; the engine's client side keeps the upstream (recursive-looking) flags.
func SetAuthoritativeResponses(on bool) { authoritativeMode.Store(on) }

// AuthoritativeResponses reports whether authoritative flags are on.
func AuthoritativeResponses() bool { return authoritativeMode.Load() }

func applyAuthoritativeFlags(flags uint16) uint16 {
	if !authoritativeMode.Load() {
		return flags
	}
	const (
		flagAA uint16 = 1 << 10
		flagRA uint16 = 1 << 7
	)
	return (flags | flagAA) &^ flagRA
}

// ZoneInfo describes the tunnel zone as a plain authoritative server would publish it.
type ZoneInfo struct {
	Zone       string // lowercase, no trailing dot
	NSHost     string // e.g. ns.example.com
	Hostmaster string // SOA RNAME, e.g. hostmaster.example.com
	Serial     uint32
	TTL        uint32 // TTL of SOA/NS answers
	NegTTL     uint32 // SOA MINIMUM (negative caching TTL)
}

var errZoneName = errors.New("name outside zone")

// BuildZoneResponse answers a non-tunnel query for a name at or below zone.Zone:
//   - apex SOA / NS / ANY get real records;
//   - everything else gets NOERROR/NODATA with the SOA in the authority section (RFC 2308).
//
// NXDOMAIN is deliberately never used: resolvers with QNAME minimisation (RFC 9156) and
// NXDOMAIN-cut (RFC 8020) would then stop before sending the full tunnel query.
func BuildZoneResponse(request []byte, parsed LitePacket, zone ZoneInfo, qname string, qtype uint16) ([]byte, error) {
	if len(request) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}
	if !isLikelyDNSRequestHeader(parsed.Header) {
		return nil, ErrNotDNSRequest
	}
	name := strings.TrimSuffix(strings.ToLower(qname), ".")
	z := strings.TrimSuffix(strings.ToLower(zone.Zone), ".")
	if z == "" || (name != z && !strings.HasSuffix(name, "."+z)) {
		return nil, errZoneName
	}
	apex := name == z

	var answers, authority [][]byte
	soa := func(owner []byte) []byte {
		rdata := append(vxEncodeName(zone.NSHost), vxEncodeName(zone.Hostmaster)...)
		var nums [20]byte
		binary.BigEndian.PutUint32(nums[0:4], zone.Serial)
		binary.BigEndian.PutUint32(nums[4:8], 3600)     // refresh
		binary.BigEndian.PutUint32(nums[8:12], 600)     // retry
		binary.BigEndian.PutUint32(nums[12:16], 604800) // expire
		binary.BigEndian.PutUint32(nums[16:20], zone.NegTTL)
		rdata = append(rdata, nums[:]...)
		return buildRR(owner, Enums.DNS_RECORD_TYPE_SOA, zone.TTL, rdata)
	}
	ns := func(owner []byte) []byte {
		return buildRR(owner, Enums.DNS_RECORD_TYPE_NS, zone.TTL, vxEncodeName(zone.NSHost))
	}
	qnamePtr := []byte{0xC0, 0x0C} // the question name always starts at offset 12
	zoneOwner := qnamePtr
	if !apex {
		zoneOwner = vxEncodeName(z)
	}
	switch {
	case apex && qtype == Enums.DNS_RECORD_TYPE_SOA:
		answers = append(answers, soa(qnamePtr))
	case apex && qtype == Enums.DNS_RECORD_TYPE_NS:
		answers = append(answers, ns(qnamePtr))
	case apex && qtype == 255: // ANY
		answers = append(answers, soa(qnamePtr), ns(qnamePtr))
	default:
		authority = append(authority, soa(zoneOwner))
	}
	return assembleZoneResponse(request, parsed, Enums.DNSR_CODE_NO_ERROR, answers, authority, true)
}

// BuildRefusedNonAuthoritative answers a query for a zone this server does not serve,
// the way a non-recursive authoritative server does (REFUSED, AA=0, RA=0).
func BuildRefusedNonAuthoritative(request []byte, parsed LitePacket) ([]byte, error) {
	if len(request) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}
	if !isLikelyDNSRequestHeader(parsed.Header) {
		return nil, ErrNotDNSRequest
	}
	return assembleZoneResponse(request, parsed, Enums.DNSR_CODE_REFUSED, nil, nil, false)
}

func assembleZoneResponse(request []byte, parsed LitePacket, rcode uint8, answers, authority [][]byte, aa bool) ([]byte, error) {
	optStart, optLen := findOPTRecordRange(request, parsed.Header, parsed.QuestionEndOffset)
	questionLen := 0
	if parsed.QuestionEndOffset >= dnsHeaderSize && parsed.QuestionEndOffset <= len(request) {
		questionLen = parsed.QuestionEndOffset - dnsHeaderSize
	}
	size := dnsHeaderSize + questionLen + optLen
	for _, rr := range answers {
		size += len(rr)
	}
	for _, rr := range authority {
		size += len(rr)
	}
	out := make([]byte, dnsHeaderSize, size)
	flags := buildResponseFlags(parsed.Header.Flags, rcode)
	const (
		flagAA uint16 = 1 << 10
		flagRA uint16 = 1 << 7
	)
	flags &^= flagRA
	if aa {
		flags |= flagAA
	} else {
		flags &^= flagAA
	}
	binary.BigEndian.PutUint16(out[0:2], parsed.Header.ID)
	binary.BigEndian.PutUint16(out[2:4], flags)
	qd := parsed.Header.QDCount
	if questionLen == 0 {
		qd = 0
	}
	binary.BigEndian.PutUint16(out[4:6], qd)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(out[8:10], uint16(len(authority)))
	binary.BigEndian.PutUint16(out[10:12], uint16(getARCount(optLen)))
	if questionLen > 0 {
		out = append(out, request[dnsHeaderSize:parsed.QuestionEndOffset]...)
	}
	for _, rr := range answers {
		out = append(out, rr...)
	}
	for _, rr := range authority {
		out = append(out, rr...)
	}
	if optLen > 0 {
		out = append(out, request[optStart:optStart+optLen]...)
	}
	return out, nil
}

func buildRR(owner []byte, rrType uint16, ttl uint32, rdata []byte) []byte {
	rr := make([]byte, 0, len(owner)+10+len(rdata))
	rr = append(rr, owner...)
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], rrType)
	binary.BigEndian.PutUint16(fixed[2:4], 1) // IN
	binary.BigEndian.PutUint32(fixed[4:8], ttl)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
	rr = append(rr, fixed[:]...)
	return append(rr, rdata...)
}

// encodeDNSName encodes a dotted name in uncompressed wire format (labels > 63 bytes are cut).
func vxEncodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	out := make([]byte, 0, len(name)+2)
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if label == "" {
				continue
			}
			if len(label) > 63 {
				label = label[:63]
			}
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
	}
	return append(out, 0)
}
