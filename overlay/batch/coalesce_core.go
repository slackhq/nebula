package batch

import (
	"bytes"
	"encoding/binary"
)

// flowKey identifies a transport flow by {src, dst, sport, dport, family}.
// Comparable, so map lookups and linear scans over the slot list stay tight.
// Shared by the TCP and UDP coalescers; each coalescer keeps its own
// openSlots map, so a TCP and UDP flow on the same 5-tuple-without-proto
// never alias.
type flowKey struct {
	src, dst     [16]byte
	sport, dport uint16
	isV6         bool
}

// initialSlots is the starting capacity of the slot pool. One flow per
// packet is the worst case so this matches a typical carrier-side
// recvmmsg batch on the encrypted UDP socket.
const initialSlots = 64

// parsedIP is the IP-level result of parseIPPrologue. The caller layers
// L4-specific parsing (TCP / UDP) on top.
type parsedIP struct {
	fk       flowKey
	ipHdrLen int
	// pkt is the original buffer trimmed to the IP-declared total length.
	// Anything below the IP layer (transport parsers) should slice into
	// pkt rather than the unbounded original.
	pkt []byte
}

// parseIPPrologue extracts the IP-level fields the coalescers care about:
// IHL/payload length, version, src/dst addresses, and the L4 protocol byte.
// Returns ok=false for malformed input, IPv4 with options or fragmentation,
// or IPv6 with extension headers (all rejected by both coalescers in
// identical ways before this refactor).
//
// On success, p.pkt is len-trimmed to the IP-declared length so callers
// don't have to repeat the trim. wantProto is the IANA protocol number to
// require (6 for TCP, 17 for UDP); ok=false for any other value.
func parseIPPrologue(pkt []byte, wantProto byte) (parsedIP, bool) {
	var p parsedIP
	if len(pkt) < 20 {
		return p, false
	}
	v := pkt[0] >> 4
	switch v {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl != 20 {
			return p, false
		}
		if pkt[9] != wantProto {
			return p, false
		}
		// Reject actual fragmentation (MF or non-zero frag offset).
		if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
			return p, false
		}
		totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen > len(pkt) || totalLen < ihl {
			return p, false
		}
		p.ipHdrLen = 20
		p.fk.isV6 = false
		copy(p.fk.src[:4], pkt[12:16])
		copy(p.fk.dst[:4], pkt[16:20])
		p.pkt = pkt[:totalLen]
	case 6:
		if len(pkt) < 40 {
			return p, false
		}
		if pkt[6] != wantProto {
			return p, false
		}
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if 40+payloadLen > len(pkt) {
			return p, false
		}
		p.ipHdrLen = 40
		p.fk.isV6 = true
		copy(p.fk.src[:], pkt[8:24])
		copy(p.fk.dst[:], pkt[24:40])
		p.pkt = pkt[:40+payloadLen]
	default:
		return p, false
	}
	return p, true
}

// ipHeadersMatch compares the IP portion of two packet header prefixes for
// byte-for-byte equality on every field that must be identical across
// coalesced segments. Size/IPID/IPCsum and the 2-bit IP-level ECN field are
// masked out — the appendPayload step merges CE into the seed.
//
// The transport (L4) portion of the header is checked separately by the
// per-protocol matcher.
func ipHeadersMatch(a, b []byte, isV6 bool) bool {
	if isV6 {
		// IPv6: byte 0 = version/TC[7:4], byte 1 = TC[3:0]/flow[19:16],
		// bytes [2:4] = flow[15:0], [6:8] = next_hdr/hop, [8:40] = src+dst.
		// ECN lives in TC[1:0] = byte 1 mask 0x30. Skip [4:6] payload_len.
		if a[0] != b[0] {
			return false
		}
		if a[1]&^0x30 != b[1]&^0x30 {
			return false
		}
		if !bytes.Equal(a[2:4], b[2:4]) {
			return false
		}
		if !bytes.Equal(a[6:40], b[6:40]) {
			return false
		}
		return true
	}
	// IPv4: byte 0 = version/IHL, byte 1 = DSCP(6)|ECN(2),
	// [6:10] flags/fragoff/TTL/proto, [12:20] src+dst.
	// Skip [2:4] total len, [4:6] id, [10:12] csum.
	if a[0] != b[0] {
		return false
	}
	if a[1]&^0x03 != b[1]&^0x03 {
		return false
	}
	if !bytes.Equal(a[6:10], b[6:10]) {
		return false
	}
	if !bytes.Equal(a[12:20], b[12:20]) {
		return false
	}
	return true
}

// mergeECNIntoSeed ORs the 2-bit IP-level ECN field of pkt's IP header
// onto the seed's IP header, so a CE mark on any coalesced segment
// propagates to the final superpacket. (CE is 0b11; ORing yields CE if
// any segment carried it.) Used by both TCP and UDP coalescers, so the
// invariant lives in one place.
func mergeECNIntoSeed(seedHdr, pktHdr []byte, isV6 bool) {
	if isV6 {
		seedHdr[1] |= pktHdr[1] & 0x30
	} else {
		seedHdr[1] |= pktHdr[1] & 0x03
	}
}
