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
// coalesced segments. Size/IPID/IPCsum are masked out. The full DSCP/ECN
// byte (IPv4 ToS / IPv6 traffic class) is compared, matching Linux kernel
// GRO: segments with differing ECN codepoints must not coalesce, otherwise
// ORing e.g. ECT(0) with ECT(1) would fabricate a false CE (congestion)
// mark or mark a Not-ECT flow as ECN-capable.
//
// The transport (L4) portion of the header is checked separately by the
// per-protocol matcher.
func ipHeadersMatch(a, b []byte, isV6 bool) bool {
	if isV6 {
		// IPv6: byte 0 = version/TC[7:4], byte 1 = TC[3:0]/flow[19:16],
		// bytes [2:4] = flow[15:0], [6:8] = next_hdr/hop, [8:40] = src+dst.
		// Compare byte 1 fully so ECN (TC[1:0]) must match. Skip [4:6] payload_len.
		if a[0] != b[0] {
			return false
		}
		if a[1] != b[1] {
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
	// Compare byte 1 fully so ECN must match.
	// Skip [2:4] total len, [4:6] id, [10:12] csum.
	if a[0] != b[0] {
		return false
	}
	if a[1] != b[1] {
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

// Arena is an injectable byte-slab that hands out non-overlapping borrowed
// slices via Reserve and releases them in bulk via Reset.
type Arena struct {
	buf []byte
}

// NewArena returns an Arena with a pre-allocated backing of the given
// capacity. Pass 0 if you don't intend to call Reserve (e.g. a test that
// only feeds the coalescer pre-made []byte packets via Commit).
func NewArena(capacity int) *Arena {
	return &Arena{buf: make([]byte, 0, capacity)}
}

// Reserve hands out a non-overlapping sz-byte slice from the arena. If the
// request doesn't fit the current backing, a fresh, larger backing is
// allocated; already-borrowed slices reference the old backing and remain
// valid until Reset.
func (a *Arena) Reserve(sz int) []byte {
	if len(a.buf)+sz > cap(a.buf) {
		newCap := max(cap(a.buf)*2, sz)
		a.buf = make([]byte, 0, newCap)
	}
	start := len(a.buf)
	a.buf = a.buf[:start+sz]
	return a.buf[start : start+sz : start+sz]
}

// Reset releases every slice handed out since the last Reset. Callers must
// not use any previously-borrowed slice after this returns. The underlying
// backing array is retained so subsequent Reserves don't re-allocate.
func (a *Arena) Reset() {
	a.buf = a.buf[:0]
}

// Reserver hands out an sz-byte slice valid until its Resetter runs.
type Reserver func(sz int) []byte

// Resetter clears all reservations held by a Reserver. Only the arena's
// owner holds one; lanes inside a MultiCoalescer get nil.
type Resetter func()
