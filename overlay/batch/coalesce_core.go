package batch

import (
	"bytes"
	"encoding/binary"
)

// flowKey identifies a transport flow by {src, dst, sport, dport, family}.
// Comparable, so map lookups and linear scans over the slot list stay tight.
// Shared by the TCP and UDP coalescers; each coalescer keeps its own
// openSlots map, so a TCP and UDP flow on the same 5-tuple-without-proto never alias.
type flowKey struct {
	src, dst     [16]byte
	sport, dport uint16
	isV6         bool
}

// initialSlots is the starting capacity of the slot pool.
// One flow per packet is the worst case,
// so this matches a typical carrier-side recvmmsg batch on the UDP socket.
const initialSlots = 64

// parseIPAt validates the IP header for lane parsing. newPacket already resolved the L4 protocol
// and offset for the firewall, so there is no proto sniff here; the caller's ipHdrLen is
// cross-checked instead. A plain header (v4 IHL 20, v6 exactly 40) is the only coalesceable
// shape. The v6 check is load-bearing: it rejects extension-header packets whose L4 is not at
// byte 40.
//
// The prologues fill fk's addresses and family in place (ports belong to the L4 parser; fk must
// be zero on entry so the v4 path leaves src[4:]/dst[4:] clear for map equality) and return pkt
// trimmed to the IP-declared length. The receiver-as-out-pointer shape is deliberate: these
// functions are too big to inline, and returning structs by value put five 64-byte copies on the
// per-packet path.
func (fk *flowKey) parseIPAt(pkt []byte, ipHdrLen int) ([]byte, bool) {
	if len(pkt) < 20 {
		return nil, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if ipHdrLen != 20 {
			return nil, false
		}
		return fk.parseIPv4Prologue(pkt)
	case 6:
		if ipHdrLen != 40 || len(pkt) < 40 {
			return nil, false
		}
		return fk.parseIPv6Prologue(pkt)
	}
	return nil, false
}

// parseIPv4Prologue is the shared IPv4 tail of the prologue entries; the caller has verified
// len(pkt) >= 20 and the version.
func (fk *flowKey) parseIPv4Prologue(pkt []byte) ([]byte, bool) {
	ihl := int(pkt[0]&0x0f) * 4
	if ihl != 20 {
		return nil, false
	}
	// Reject any fragmentation (MF or nonzero offset). The dispatcher already gated FragAny; kept
	// as defense in depth, since a fragment folded into a superpacket would corrupt reassembly.
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen > len(pkt) || totalLen < ihl {
		return nil, false
	}
	fk.isV6 = false
	copy(fk.src[:4], pkt[12:16])
	copy(fk.dst[:4], pkt[16:20])
	return pkt[:totalLen], true
}

// parseIPv6Prologue is the shared IPv6 tail; the caller has verified len(pkt) >= 40, the version,
// and that the L4 header sits at byte 40.
func (fk *flowKey) parseIPv6Prologue(pkt []byte) ([]byte, bool) {
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if 40+payloadLen > len(pkt) {
		return nil, false
	}
	fk.isV6 = true
	copy(fk.src[:], pkt[8:24])
	copy(fk.dst[:], pkt[24:40])
	return pkt[:40+payloadLen], true
}

// ipHeadersMatch compares the IP portion of two packet header prefixes for
// byte-for-byte equality on every field that must be identical across coalesced segments.
// Size/IPID/IPCsum are masked out.
// The full DSCP/ECN byte (IPv4 ToS / IPv6 traffic class) is compared, matching Linux kernel GRO:
// segments with differing ECN codepoints must not coalesce,
// otherwise ORing e.g. ECT(0) with ECT(1) would fabricate a false CE (congestion) mark or mark a Not-ECT flow as ECN-capable.
//
// The transport (L4) portion of the header is checked separately by the per-protocol matcher.
func ipHeadersMatch(a, b []byte, isV6 bool) bool {
	if isV6 {
		// IPv6: [0:4] = version/TC/flow label (TC[1:0] is ECN, so the full TC byte must match),
		// [6:40] = next_hdr/hop + src + dst. Skip [4:6] payload_len.
		return bytes.Equal(a[:4], b[:4]) && bytes.Equal(a[6:40], b[6:40])
	}
	// IPv4: [0:2] = version/IHL + DSCP|ECN (full ECN byte must match),
	// [6:10] = flags/fragoff/TTL/proto, [12:20] = src+dst.
	// Skip [2:4] total len, [4:6] id, [10:12] csum.
	return bytes.Equal(a[:2], b[:2]) && bytes.Equal(a[6:10], b[6:10]) && bytes.Equal(a[12:20], b[12:20])
}

// ipv4FlagDF is the Don't Fragment bit in the IPv4 flags byte (header byte 6).
const ipv4FlagDF = 0x40

// ipv4CanCoalesceID reports whether an IPv4 packet whose header starts at
// nextHdr may join a chain whose seed header is seedHdr as segment index seg
// (the seed is segment 0). Kernel GSO re-stamps outgoing segment IDs as
// seed_id+n, so coalescing is only transparent when that re-stamp is either
// harmless (DF set: RFC 6864 atomic datagrams, the ID carries no meaning) or
// reproduces the original IDs exactly (DF clear + IDs already sequential —
// the same admission rule kernel GRO applies). Without this, a DF=0 sender
// with non-sequential IDs (e.g. OpenBSD's randomized IDs) could have IDs
// rewritten into ranges that collide across superpackets, corrupting
// reassembly if the packets are fragmented after the TUN write.
//
// DF itself is guaranteed uniform across a chain by ipHeadersMatch (byte 6
// is inside its compared range), so checking the seed's copy suffices.
func ipv4CanCoalesceID(seedHdr, nextHdr []byte, seg int) bool {
	if seedHdr[6]&ipv4FlagDF != 0 {
		return true
	}
	expect := binary.BigEndian.Uint16(seedHdr[4:6]) + uint16(seg)
	return binary.BigEndian.Uint16(nextHdr[4:6]) == expect
}

// Arena is an injectable byte-slab that hands out non-overlapping borrowed
// slices via Reserve and releases them in bulk via Reset.
type Arena struct {
	buf []byte
}

// NewArena returns an Arena with a pre-allocated backing of the given capacity.
func NewArena(capacity int) *Arena {
	return &Arena{buf: make([]byte, 0, capacity)}
}

// Reserve hands out a non-overlapping sz-byte slice from the arena.
// If the request doesn't fit the current backing, a fresh, larger backing is allocated.
// Already-borrowed slices reference the old backing and remain valid until Reset.
func (a *Arena) Reserve(sz int) []byte {
	if len(a.buf)+sz > cap(a.buf) {
		newCap := max(cap(a.buf)*2, sz)
		a.buf = make([]byte, 0, newCap)
	}
	start := len(a.buf)
	a.buf = a.buf[:start+sz]
	return a.buf[start : start+sz : start+sz]
}

// Reset releases every slice handed out since the last Reset.
// Callers must not use any previously-borrowed slice after this returns.
// The underlying backing array is retained so subsequent Reserves don't re-allocate.
func (a *Arena) Reset() {
	a.buf = a.buf[:0]
}
