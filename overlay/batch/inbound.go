package batch

import (
	"encoding/binary"
	"errors"

	"github.com/slackhq/nebula/firewall"
)

// IANA protocol numbers we recognise during the inbound parse. Kept local
// (rather than reaching for the firewall constants for every one of these)
// so the byte-comparison hot path doesn't depend on cross-package values.
const (
	ipProtoICMP         = 1
	ipProtoIPv6Fragment = 44
	ipProtoESP          = 50
	ipProtoAH           = 51
	ipProtoICMPv6       = 58
	ipProtoNoNextHdr    = 59

	icmpv6TypeEchoRequest = 128
	icmpv6TypeEchoReply   = 129
)

// Packet parse errors — the canonical sentinel set for IP+L4 parsing.
// Both inbound and outbound callers share this surface, so any code path
// that ends up at firewall.PacketKey reports drops with the same errors.
var (
	ErrPacketTooShort          = errors.New("packet is too short")
	ErrUnknownIPVersion        = errors.New("packet is an unknown ip version")
	ErrIPv4InvalidHeaderLength = errors.New("invalid ipv4 header length")
	ErrIPv4PacketTooShort      = errors.New("ipv4 packet is too short")
	ErrIPv6PacketTooShort      = errors.New("ipv6 packet is too short")
	ErrIPv6CouldNotFindPayload = errors.New("could not find payload in ipv6 packet")
)

// RxKind discriminates how an inbound plaintext packet should be committed
// after its firewall.Packet has been built. RxKindPassthrough means the
// IP shape is valid (firewall could match on it) but the coalescer's
// strict checks reject it — caller should still write it via the
// passthrough lane.
type RxKind uint8

const (
	RxKindPassthrough RxKind = iota
	RxKindTCP
	RxKindUDP
)

// RxParsed is the unified result of one IP+L4 walk:
//   - Key: the firewall's conntrack/cache lookup key. The dense form lets
//     firewall.Drop hit conntrack without ever filling the rich Packet's
//     netip.Addr fields. On a conntrack miss, Drop hydrates the caller's
//     Packet from Key.
//   - tcp/udp: the coalescer hint so commitParsed doesn't re-walk the
//     headers. Meaningful only when Kind is RxKindTCP / RxKindUDP.
type RxParsed struct {
	Kind RxKind
	Key  firewall.PacketKey
	tcp  parsedTCP
	udp  parsedUDP
}

// ParsePacket walks an IP packet once and fills parsed.Key. When incoming
// is true and the L4 shape is coalesce-eligible, also fills parsed.tcp /
// parsed.udp so CommitInbound can dispatch into the coalescer without
// re-walking the headers.
//
// Direction selects the Key orientation:
//
//	incoming=true  → wire src → Key.RemoteAddr/Port, wire dst → Key.LocalAddr/Port
//	incoming=false → wire src → Key.LocalAddr/Port,  wire dst → Key.RemoteAddr/Port
//
// ICMP always lands the identifier in Key.RemotePort, regardless of direction.
//
// Eligibility rules for the coalescer hint match the coalescer's own
// parseTCPBase/parseUDP:
//   - IPv4 strict: IHL == 20, no fragmentation (MF or offset), proto TCP/UDP.
//   - IPv6 strict: NextHeader is directly TCP or UDP (no extension headers).
//
// The hint is only filled for incoming packets, since the outbound path
// does not feed an inbound coalescer. Outbound callers see Kind stay at
// RxKindPassthrough and parsed.tcp/udp stay zero.
func ParsePacket(pkt []byte, incoming bool, parsed *RxParsed) error {
	parsed.Kind = RxKindPassthrough
	// Reset Key in full: v4 only writes the low 4 bytes of each address
	// field, so without this a v6 call followed by a v4 reusing the same
	// RxParsed would inherit the high 12 bytes — breaking the conntrack
	// map equality for v4 flows.
	parsed.Key = firewall.PacketKey{}
	if len(pkt) < 1 {
		return ErrPacketTooShort
	}
	switch pkt[0] >> 4 {
	case 4:
		return parsePacketV4(pkt, incoming, parsed)
	case 6:
		return parsePacketV6(pkt, incoming, parsed)
	}
	return ErrUnknownIPVersion
}

// parsePacketV4 fills parsed.Key from an IPv4 packet. Direction selects
// Local/Remote orientation. When incoming and the shape is strict, also
// fills the coalescer hint.
func parsePacketV4(pkt []byte, incoming bool, parsed *RxParsed) error {
	if len(pkt) < 20 {
		return ErrIPv4PacketTooShort
	}
	ihl := int(pkt[0]&0x0f) << 2
	if ihl < 20 {
		return ErrIPv4InvalidHeaderLength
	}
	flagsfrags := binary.BigEndian.Uint16(pkt[6:8])
	parsed.Key.Fragment = (flagsfrags & 0x1FFF) != 0
	parsed.Key.Protocol = pkt[9]
	parsed.Key.IsV6 = false

	// minFwPacketLen (4) is the L4-header prefix the firewall needs to pull
	// ports; ICMP needs two extra bytes for the identifier.
	minLen := ihl
	if !parsed.Key.Fragment {
		if parsed.Key.Protocol == firewall.ProtoICMP {
			minLen += 4 + 2
		} else {
			minLen += 4
		}
	}
	if len(pkt) < minLen {
		return ErrIPv4InvalidHeaderLength
	}

	if incoming {
		copy(parsed.Key.RemoteAddr[:4], pkt[12:16])
		copy(parsed.Key.LocalAddr[:4], pkt[16:20])
	} else {
		copy(parsed.Key.LocalAddr[:4], pkt[12:16])
		copy(parsed.Key.RemoteAddr[:4], pkt[16:20])
	}

	switch {
	case parsed.Key.Fragment:
		parsed.Key.RemotePort = 0
		parsed.Key.LocalPort = 0
	case parsed.Key.Protocol == firewall.ProtoICMP:
		parsed.Key.RemotePort = binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6])
		parsed.Key.LocalPort = 0
	case incoming:
		parsed.Key.RemotePort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		parsed.Key.LocalPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	default:
		parsed.Key.LocalPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		parsed.Key.RemotePort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	}

	// Coalescer hint is inbound-only: no inbound coalescer fires on outgoing.
	if !incoming {
		return nil
	}
	// Coalescer-eligible? Strict shape: IHL==20, no MF/offset, TCP or UDP.
	if ihl != 20 || (flagsfrags&0x3FFF) != 0 {
		return nil
	}
	if parsed.Key.Protocol != ipProtoTCP && parsed.Key.Protocol != ipProtoUDP {
		return nil
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen > len(pkt) || totalLen < 20 {
		return nil
	}
	pktTrim := pkt[:totalLen]

	switch parsed.Key.Protocol {
	case ipProtoTCP:
		fillParsedTCPv4(pktTrim, parsed)
	case ipProtoUDP:
		fillParsedUDPv4(pktTrim, parsed)
	}
	return nil
}

// fillParsedTCPv4 fills parsed.tcp from a strict-shape IPv4+TCP packet
// already validated to have IHL==20 and to be totalLen-trimmed.
func fillParsedTCPv4(pkt []byte, parsed *RxParsed) {
	if len(pkt) < 40 { // IPv4(20) + min TCP(20)
		return
	}
	tcpOff := int(pkt[32]>>4) * 4
	if tcpOff < 20 || tcpOff > 60 {
		return
	}
	if len(pkt) < 20+tcpOff {
		return
	}
	p := &parsed.tcp
	p.ipHdrLen = 20
	p.tcpHdrLen = tcpOff
	p.hdrLen = 20 + tcpOff
	p.payLen = len(pkt) - p.hdrLen
	p.seq = binary.BigEndian.Uint32(pkt[24:28])
	p.flags = pkt[33]
	p.fk.isV6 = false
	p.fk.sport = parsed.Key.RemotePort
	p.fk.dport = parsed.Key.LocalPort
	copy(p.fk.src[:4], pkt[12:16])
	copy(p.fk.dst[:4], pkt[16:20])
	parsed.Kind = RxKindTCP
}

// fillParsedUDPv4 fills parsed.udp from a strict-shape IPv4+UDP packet.
func fillParsedUDPv4(pkt []byte, parsed *RxParsed) {
	if len(pkt) < 28 { // IPv4(20) + UDP(8)
		return
	}
	udpLen := int(binary.BigEndian.Uint16(pkt[24:26]))
	if udpLen < 8 || udpLen > len(pkt)-20 {
		return
	}
	p := &parsed.udp
	p.ipHdrLen = 20
	p.hdrLen = 28
	p.payLen = udpLen - 8
	p.fk.isV6 = false
	p.fk.sport = parsed.Key.RemotePort
	p.fk.dport = parsed.Key.LocalPort
	copy(p.fk.src[:4], pkt[12:16])
	copy(p.fk.dst[:4], pkt[16:20])
	parsed.Kind = RxKindUDP
}

// parsePacketV6 fills parsed.Key from an IPv6 packet. Direction selects
// Local/Remote orientation. The coalescer hint fast path only triggers
// when NextHeader is directly TCP or UDP — any extension header chain
// falls into the lenient walk below, and the hint stays unfilled.
func parsePacketV6(pkt []byte, incoming bool, parsed *RxParsed) error {
	if len(pkt) < 40 {
		return ErrIPv6PacketTooShort
	}
	parsed.Key.IsV6 = true
	if incoming {
		copy(parsed.Key.RemoteAddr[:], pkt[8:24])
		copy(parsed.Key.LocalAddr[:], pkt[24:40])
	} else {
		copy(parsed.Key.LocalAddr[:], pkt[8:24])
		copy(parsed.Key.RemoteAddr[:], pkt[24:40])
	}

	if proto := pkt[6]; proto == ipProtoTCP || proto == ipProtoUDP {
		// Strict v6: ports are at the IP header end. Always fill key; only
		// fill the coalescer hint if the L4 shape passes.
		if len(pkt) < 44 {
			return ErrIPv6PacketTooShort
		}
		parsed.Key.Protocol = proto
		parsed.Key.Fragment = false
		if incoming {
			parsed.Key.RemotePort = binary.BigEndian.Uint16(pkt[40:42])
			parsed.Key.LocalPort = binary.BigEndian.Uint16(pkt[42:44])
		} else {
			parsed.Key.LocalPort = binary.BigEndian.Uint16(pkt[40:42])
			parsed.Key.RemotePort = binary.BigEndian.Uint16(pkt[42:44])
		}

		// Coalescer hint is inbound-only.
		if !incoming {
			return nil
		}
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if 40+payloadLen > len(pkt) {
			return nil
		}
		pktTrim := pkt[:40+payloadLen]

		switch proto {
		case ipProtoTCP:
			fillParsedTCPv6(pktTrim, parsed)
		case ipProtoUDP:
			fillParsedUDPv6(pktTrim, parsed)
		}
		return nil
	}

	// Slow path: walk extension header chain. Coalescer hint never fires
	// here, so direction only matters for L4 port orientation.
	return walkV6Headers(pkt, incoming, parsed)
}

func fillParsedTCPv6(pkt []byte, parsed *RxParsed) {
	if len(pkt) < 60 { // IPv6(40) + min TCP(20)
		return
	}
	tcpOff := int(pkt[52]>>4) * 4
	if tcpOff < 20 || tcpOff > 60 {
		return
	}
	if len(pkt) < 40+tcpOff {
		return
	}
	p := &parsed.tcp
	p.ipHdrLen = 40
	p.tcpHdrLen = tcpOff
	p.hdrLen = 40 + tcpOff
	p.payLen = len(pkt) - p.hdrLen
	p.seq = binary.BigEndian.Uint32(pkt[44:48])
	p.flags = pkt[53]
	p.fk.isV6 = true
	p.fk.sport = parsed.Key.RemotePort
	p.fk.dport = parsed.Key.LocalPort
	copy(p.fk.src[:], pkt[8:24])
	copy(p.fk.dst[:], pkt[24:40])
	parsed.Kind = RxKindTCP
}

func fillParsedUDPv6(pkt []byte, parsed *RxParsed) {
	if len(pkt) < 48 { // IPv6(40) + UDP(8)
		return
	}
	udpLen := int(binary.BigEndian.Uint16(pkt[44:46]))
	if udpLen < 8 || udpLen > len(pkt)-40 {
		return
	}
	p := &parsed.udp
	p.ipHdrLen = 40
	p.hdrLen = 48
	p.payLen = udpLen - 8
	p.fk.isV6 = true
	p.fk.sport = parsed.Key.RemotePort
	p.fk.dport = parsed.Key.LocalPort
	copy(p.fk.src[:], pkt[8:24])
	copy(p.fk.dst[:], pkt[24:40])
	parsed.Kind = RxKindUDP
}

// walkV6Headers handles every IPv6 case the strict "NextHeader == TCP/UDP"
// fast path doesn't: ESP, NoNextHeader, ICMPv6, fragment headers (first vs
// later), AH, generic extension headers. Coalescer eligibility is always
// RxKindPassthrough on this path (parsed already initialised that way).
// Direction matters only for the L4 port orientation when the chain
// terminates at TCP/UDP.
func walkV6Headers(pkt []byte, incoming bool, parsed *RxParsed) error {
	dataLen := len(pkt)
	protoAt := 6
	offset := 40
	next := 0
	for {
		if protoAt >= dataLen {
			break
		}
		proto := pkt[protoAt]
		switch proto {
		case ipProtoESP, ipProtoNoNextHdr:
			parsed.Key.Protocol = proto
			parsed.Key.RemotePort = 0
			parsed.Key.LocalPort = 0
			parsed.Key.Fragment = false
			return nil

		case ipProtoICMPv6:
			if dataLen < offset+6 {
				return ErrIPv6PacketTooShort
			}
			parsed.Key.Protocol = proto
			parsed.Key.LocalPort = 0
			switch pkt[offset+1] {
			case icmpv6TypeEchoRequest, icmpv6TypeEchoReply:
				parsed.Key.RemotePort = binary.BigEndian.Uint16(pkt[offset+4 : offset+6])
			default:
				parsed.Key.RemotePort = 0
			}
			parsed.Key.Fragment = false
			return nil

		case ipProtoTCP, ipProtoUDP:
			// Reachable when an extension-header chain ends at TCP/UDP. The
			// strict-eligible fast path above already handled the no-extension
			// case; here we only fill firewall ports and stay passthrough.
			if dataLen < offset+4 {
				return ErrIPv6PacketTooShort
			}
			parsed.Key.Protocol = proto
			if incoming {
				parsed.Key.RemotePort = binary.BigEndian.Uint16(pkt[offset : offset+2])
				parsed.Key.LocalPort = binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
			} else {
				parsed.Key.LocalPort = binary.BigEndian.Uint16(pkt[offset : offset+2])
				parsed.Key.RemotePort = binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
			}
			parsed.Key.Fragment = false
			return nil

		case ipProtoIPv6Fragment:
			if dataLen < offset+8 {
				return ErrIPv6PacketTooShort
			}
			fragmentOffset := binary.BigEndian.Uint16(pkt[offset+2:offset+4]) &^ uint16(0x7)
			if fragmentOffset != 0 {
				// Non-first fragment: report the fragment flag and stop.
				parsed.Key.Protocol = pkt[offset]
				parsed.Key.Fragment = true
				parsed.Key.RemotePort = 0
				parsed.Key.LocalPort = 0
				return nil
			}
			next = 8

		case ipProtoAH:
			if dataLen <= offset+1 {
				break
			}
			next = int(pkt[offset+1]+2) << 2

		default:
			if dataLen <= offset+1 {
				break
			}
			next = int(pkt[offset+1]+1) << 3
		}

		if next <= 0 {
			next = 8
		}
		protoAt = offset
		offset = offset + next
	}
	return ErrIPv6CouldNotFindPayload
}

// CommitInbound dispatches pkt to the appropriate lane using parsed.Kind,
// skipping the IP+L4 re-parse that MultiCoalescer.Commit would otherwise
// do. Borrowed slice contract is identical to MultiCoalescer.Commit.
func (m *MultiCoalescer) CommitInbound(pkt []byte, parsed *RxParsed) error {
	switch parsed.Kind {
	case RxKindTCP:
		if m.tcp != nil {
			return m.tcp.commitParsed(pkt, parsed.tcp)
		}
	case RxKindUDP:
		if m.udp != nil {
			return m.udp.commitParsed(pkt, parsed.udp)
		}
	}
	return m.pt.Commit(pkt)
}
