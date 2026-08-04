package batch

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"

	"github.com/slackhq/nebula/overlay/tio"
)

// ipProtoTCP is the IANA protocol number for TCP. Defined here to help Windows out.
const ipProtoTCP = 6

// tcpCoalesceBufSize caps total bytes per superpacket. Mirrors the kernel's
// sk_gso_max_size of ~64KiB; anything beyond this would be rejected anyway.
const tcpCoalesceBufSize = 65535

// tcpCoalesceMaxSegs caps how many segments we'll coalesce into a single
// superpacket. Keeping this well below the kernel's TSO ceiling bounds latency.
const tcpCoalesceMaxSegs = 64

// tcpCoalesceHdrCap is the scratch space we copy a seed's IP+TCP header
// into. IPv6 (40) + TCP with full options (60) = 100 bytes.
const tcpCoalesceHdrCap = 100

// coalesceSlot is one entry in the coalescer's ordered event queue. A verbatim slot holds a single
// borrowed packet emitted as-is (pure ACK, non-admissible TCP, unparseable, or oversize seed); a
// non-verbatim slot is an in-progress coalesced superpacket. payIovs are borrowed slices of the
// caller's plaintext buffers; the caller must keep them alive until Flush.
type coalesceSlot struct {
	verbatim bool
	// rawPkt is borrowed: the whole packet for verbatim slots, the seed packet for coalesce
	// slots. A slot that never grows past one segment is emitted from rawPkt so its original
	// (already valid) L4 checksum ships DATA_VALID instead of making the kernel recompute it.
	rawPkt []byte

	fk flowKey
	// hdrBuf is a mutable copy of the seed's IP+TCP header, populated on the first append. Total
	// length and the pseudo-header checksum partial are patched at flush. A slot that never grows
	// flushes from rawPkt and never touches hdrBuf.
	hdrBuf   [tcpCoalesceHdrCap]byte
	hdrLen   int
	ipHdrLen int
	isV6     bool
	gsoSize  int
	numSeg   int
	totalPay int
	nextSeq  uint32
	payIovs  [][]byte
}

// TCPCoalescer accumulates adjacent in-flow TCP data segments across multiple concurrent flows and
// emits each flow's run as a single TSO superpacket via tio.GSOWriter. Input must be in sender
// transmission order (MultiCoalescer sorts by (epoch, counter) before dispatch); slots are emitted
// in creation order, so emission reproduces transmission order except for the pure-ACK case in
// commitParsed. Owns no locks; one coalescer per TUN write queue.
type TCPCoalescer struct {
	w tio.GSOWriter

	// slots is the ordered event queue. Flush walks it once and emits each
	// entry as either a WriteGSO (coalesced) or a w.Write (verbatim).
	slots []*coalesceSlot
	// openSlots maps a flow key to its open slot so new segments can extend an in-progress
	// superpacket in O(1). Removal is what closes a chain: on PSH or a short last segment, on a
	// non-admissible packet for the flow, or in Flush.
	openSlots map[flowKey]*coalesceSlot
	// lastSlot caches the most recently touched open slot. Bulk traffic
	// arrives in same-flow runs (single-flow steady state, or GRO bursts
	// under multi-flow), so comparing the incoming key against the cached
	// slot's own fk lets the hot path skip the map lookup (and the aeshash
	// of a 38-byte key) for the length of each run.
	// Kept in lockstep with openSlots: nil whenever the slot it pointed
	// at is removed.
	lastSlot *coalesceSlot
	pool     []*coalesceSlot // free list for reuse
	l        *slog.Logger
}

// NewTCPCoalescer wraps w, returning nil if w can't accept GSO_TCP writes.
func NewTCPCoalescer(w io.Writer, l *slog.Logger) *TCPCoalescer {
	gw, ok := tio.SupportsGSO(w, tio.GSOProtoTCP)
	if !ok {
		return nil
	}
	return &TCPCoalescer{
		w:         gw,
		slots:     make([]*coalesceSlot, 0, initialSlots),
		openSlots: make(map[flowKey]*coalesceSlot, initialSlots),
		pool:      make([]*coalesceSlot, 0, initialSlots),
		l:         l,
	}
}

// parsedTCP holds the fields extracted from a single parse so later steps
// (admission, slot lookup, canAppend) don't re-walk the header.
type parsedTCP struct {
	fk       flowKey
	ipHdrLen int
	hdrLen   int
	payLen   int
	seq      uint32
	flags    byte
}

// parseAt extracts the flow key and IP/TCP offsets for a packet the dispatcher already knows is
// TCP; ipHdrLen is the upstream-resolved L4 offset (see flowKey.parseIPAt). p must be zero on
// entry and is filled in place; see flowKey.parseIPAt for why. Returns false for malformed input
// or any shape that must not coalesce (IPv4 options/fragmentation, IPv6 extension headers).
func (p *parsedTCP) parseAt(pkt []byte, ipHdrLen int) bool {
	trimmed, ok := p.fk.parseIPAt(pkt, ipHdrLen)
	if !ok {
		return false
	}
	return p.parseTail(trimmed, ipHdrLen)
}

// parseTail layers the TCP-header parse on a validated IP prologue. pkt is the trimmed packet;
// fk's addresses are already filled.
func (p *parsedTCP) parseTail(pkt []byte, ipHdrLen int) bool {
	if len(pkt) < ipHdrLen+20 {
		return false
	}
	tcpOff := int(pkt[ipHdrLen+12]>>4) * 4
	if tcpOff < 20 || tcpOff > 60 {
		return false
	}
	if len(pkt) < ipHdrLen+tcpOff {
		return false
	}
	p.ipHdrLen = ipHdrLen
	p.hdrLen = ipHdrLen + tcpOff
	p.payLen = len(pkt) - p.hdrLen
	p.fk.sport = binary.BigEndian.Uint16(pkt[ipHdrLen : ipHdrLen+2])
	p.fk.dport = binary.BigEndian.Uint16(pkt[ipHdrLen+2 : ipHdrLen+4])
	p.seq = binary.BigEndian.Uint32(pkt[ipHdrLen+4 : ipHdrLen+8])
	p.flags = pkt[ipHdrLen+13]
	return true
}

// TCP flag bits (byte 13 of the TCP header). Only the bits the coalescer consults are named;
// FIN/SYN/RST/URG/CWR are rejected by the negative mask in commitParsed.
const (
	tcpFlagPsh = 0x08
	tcpFlagAck = 0x10
	tcpFlagEce = 0x40
)

// sealAllOpen closes every open coalesce chain. Called for unparseable packets: the flow key is
// unknown, so any open chain could otherwise absorb later data and emit it ahead of this packet.
func (c *TCPCoalescer) sealAllOpen() {
	clear(c.openSlots)
	c.lastSlot = nil
}

// commitParsed commits one parsed TCP packet. The caller (dispatch, via parseAt) supplies a
// valid parse so the header is not re-walked here.
func (c *TCPCoalescer) commitParsed(pkt []byte, info *parsedTCP) error {
	// Admission: only ACK, ACK|PSH, ACK|ECE, ACK|PSH|ECE may ride a coalesce chain. CWR marks a
	// one-shot congestion transition the receiver must observe at a segment boundary. NB: AccECN
	// reuses CWR as ACE counter bits; revisit this check if inner hosts adopt AccECN.
	if info.flags&tcpFlagAck == 0 || info.flags&^(tcpFlagAck|tcpFlagPsh|tcpFlagEce) != 0 {
		// SYN/FIN/RST/URG/CWR must be observed in sequence. Seal the flow's open slot so later
		// in-flow packets cannot extend it and emit ahead of this verbatim. The len guard skips
		// hashing the 38-byte key on ack-dominant queues, where the map is almost always empty.
		if len(c.openSlots) != 0 {
			if last := c.lastSlot; last != nil && last.fk == info.fk {
				c.lastSlot = nil
			}
			delete(c.openSlots, info.fk)
		}
		c.addVerbatim(pkt)
		return nil
	}
	if info.payLen == 0 {
		// Pure ACK: no ordering obligation toward the flow's data. Delivering it after
		// later-transmitted data only makes it a stale ACK, which receivers ignore. Not sealing
		// keeps a bidirectional flow's data run coalescing across interleaved peer ACKs, matching
		// kernel GRO. This is the only place emission deviates from transmission order.
		c.addVerbatim(pkt)
		return nil
	}

	// Cached-slot fast path. Arrival isn't per-packet interleaved even with
	// many flows: wire-side GRO delivers runs of same-flow packets
	// (deliverSegments splits a superdatagram into up to 64), so the cache
	// hits for the length of each run and a miss costs one fk compare
	// before the map lookup carries the weight.
	var open *coalesceSlot
	if last := c.lastSlot; last != nil && last.fk == info.fk {
		open = last
	} else {
		open = c.openSlots[info.fk]
	}
	if open != nil {
		if c.canAppend(open, pkt, info) {
			if c.appendPayload(open, pkt, info) {
				// Chain closed (PSH or short segment): stop extending it.
				delete(c.openSlots, info.fk)
				c.lastSlot = nil
			} else {
				c.lastSlot = open
			}
			return nil
		}
		// Can't extend (seq gap from upstream loss, header change, or a full
		// chain): evict it from openSlots and fall through to seed a fresh slot.
		delete(c.openSlots, info.fk)
		if c.lastSlot == open {
			c.lastSlot = nil
		}
	}
	c.seed(pkt, info)
	return nil
}

func (c *TCPCoalescer) Flush() error {
	if c.l.Enabled(context.Background(), slog.LevelDebug) {
		c.logSeqGaps()
	}
	var first error
	for _, s := range c.slots {
		var err error
		if s.verbatim || s.numSeg == 1 {
			// A slot that never grew is byte-identical to its seed packet; ship the original so
			// its valid checksum rides the DATA_VALID path instead of a kernel software csum.
			// appendPayload only touches hdrBuf once numSeg >= 2, so rawPkt is pristine here.
			_, err = c.w.Write(s.rawPkt)
		} else {
			err = c.flushSlot(s)
		}
		if err != nil && first == nil {
			first = err
		}
		c.release(s)
	}
	clear(c.slots)
	c.slots = c.slots[:0]
	clear(c.openSlots)
	c.lastSlot = nil

	return first
}

func (c *TCPCoalescer) addVerbatim(pkt []byte) {
	s := c.take()
	s.verbatim = true
	s.rawPkt = pkt
	c.slots = append(c.slots, s)
}

func (c *TCPCoalescer) seed(pkt []byte, info *parsedTCP) {
	if info.hdrLen > tcpCoalesceHdrCap || info.hdrLen+info.payLen > tcpCoalesceBufSize {
		// Pathological shape. Can't fit our scratch, emit as-is.
		c.addVerbatim(pkt)
		return
	}
	s := c.take()
	s.verbatim = false
	// rawPkt serves the numSeg==1 fast path in Flush and is the header source for canAppend until
	// the first append copies it into hdrBuf.
	s.rawPkt = pkt
	s.hdrLen = info.hdrLen
	s.ipHdrLen = info.ipHdrLen
	s.isV6 = info.fk.isV6
	s.fk = info.fk
	s.gsoSize = info.payLen
	s.numSeg = 1
	s.totalPay = info.payLen
	s.nextSeq = info.seq + uint32(info.payLen)
	s.payIovs = append(s.payIovs[:0], pkt[info.hdrLen:info.hdrLen+info.payLen])
	c.slots = append(c.slots, s)
	if info.flags&tcpFlagPsh == 0 {
		c.openSlots[info.fk] = s
		c.lastSlot = s
	} else if last := c.lastSlot; last != nil && last.fk == info.fk {
		// PSH on the seed closes the chain immediately; it is never registered as open. Drop any
		// stale cache entry for this flow too.
		c.lastSlot = nil
	}
}

// canAppend reports whether info's packet extends the slot's seed: same header shape and stable
// contents, adjacent seq, not oversized. A closed chain never reaches here; closing removes the
// slot from openSlots, the only path in. Header reads use rawPkt because hdrBuf is populated
// lazily on the first append; every field consulted here is one the pre-flush patches never touch.
func (c *TCPCoalescer) canAppend(s *coalesceSlot, pkt []byte, info *parsedTCP) bool {
	if info.hdrLen != s.hdrLen {
		return false
	}
	if info.seq != s.nextSeq {
		return false
	}
	if s.numSeg >= tcpCoalesceMaxSegs {
		return false
	}
	if info.payLen > s.gsoSize {
		return false
	}
	if s.hdrLen+s.totalPay+info.payLen > tcpCoalesceBufSize {
		return false
	}
	// ECE state must be stable across a burst.
	// Receivers expect the flag set on every segment of a CE-echoing window or none.
	seedFlags := s.rawPkt[s.ipHdrLen+13]
	if (seedFlags^info.flags)&tcpFlagEce != 0 {
		return false
	}
	if !s.isV6 && !ipv4CanCoalesceID(s.rawPkt, pkt, s.numSeg) {
		return false
	}
	if !headersMatch(s.rawPkt[:s.hdrLen], pkt[:info.hdrLen], s.isV6, s.ipHdrLen) {
		return false
	}
	return true
}

// appendPayload folds info's packet into s and reports whether the chain is now closed: the
// segment was sub-gsoSize (kernel TSO allows only the final segment to be short) or carried PSH.
// The caller must deregister a closed slot from openSlots.
func (c *TCPCoalescer) appendPayload(s *coalesceSlot, pkt []byte, info *parsedTCP) bool {
	if s.numSeg == 1 {
		// First append: populate hdrBuf from the seed. Deferred out of seed so solo slots, which
		// flush from rawPkt, never pay the copy.
		copy(s.hdrBuf[:s.hdrLen], s.rawPkt[:s.hdrLen])
	}
	s.payIovs = append(s.payIovs, pkt[info.hdrLen:info.hdrLen+info.payLen])
	s.numSeg++
	s.totalPay += info.payLen
	s.nextSeq = info.seq + uint32(info.payLen)
	if info.flags&tcpFlagPsh != 0 {
		// Propagate PSH into the seed header so kernel TSO sets it on the last segment.
		s.hdrBuf[s.ipHdrLen+13] |= tcpFlagPsh
	}
	return info.payLen < s.gsoSize || info.flags&tcpFlagPsh != 0
}

func (c *TCPCoalescer) take() *coalesceSlot {
	if n := len(c.pool); n > 0 {
		s := c.pool[n-1]
		c.pool[n-1] = nil
		c.pool = c.pool[:n-1]
		return s
	}
	return &coalesceSlot{}
}

func (c *TCPCoalescer) release(s *coalesceSlot) {
	s.verbatim = false
	s.rawPkt = nil
	clear(s.payIovs)
	s.payIovs = s.payIovs[:0]
	s.numSeg = 0
	s.totalPay = 0
	// Zero the identity fields too: addVerbatim doesn't set them, so a
	// pooled slot reused as a verbatim must not carry a stale flow key
	// that a future refactor could mistake for real.
	s.fk = flowKey{}
	s.hdrLen = 0
	s.ipHdrLen = 0
	s.isV6 = false
	s.gsoSize = 0
	s.nextSeq = 0
	c.pool = append(c.pool, s)
}

// flushSlot patches the header and calls WriteGSO. Does not remove the slot from c.slots.
func (c *TCPCoalescer) flushSlot(s *coalesceSlot) error {
	total := s.hdrLen + s.totalPay
	l4Len := total - s.ipHdrLen
	hdr := s.hdrBuf[:s.hdrLen]

	if s.isV6 {
		binary.BigEndian.PutUint16(hdr[4:6], uint16(l4Len))
	} else {
		binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
		hdr[10] = 0
		hdr[11] = 0
		binary.BigEndian.PutUint16(hdr[10:12], ipv4HdrChecksum(hdr[:s.ipHdrLen]))
	}

	var psum uint32
	if s.isV6 {
		psum = pseudoSumIPv6(hdr[8:24], hdr[24:40], ipProtoTCP, l4Len)
	} else {
		psum = pseudoSumIPv4(hdr[12:16], hdr[16:20], ipProtoTCP, l4Len)
	}
	tcsum := s.ipHdrLen + 16
	binary.BigEndian.PutUint16(hdr[tcsum:tcsum+2], foldOnceNoInvert(psum))

	return c.w.WriteGSO(hdr[:s.ipHdrLen], hdr[s.ipHdrLen:], s.payIovs, tio.GSOProtoTCP)
}

// headersMatch compares two IP+TCP header prefixes for byte-for-byte
// equality on every field that must be identical across coalesced
// segments. Size/IPID/IPCsum/seq/flags/tcpCsum are masked out.
func headersMatch(a, b []byte, isV6 bool, ipHdrLen int) bool {
	if len(a) != len(b) {
		return false
	}
	if !ipHeadersMatch(a, b, isV6) {
		return false
	}
	// TCP: compare [0:4] ports, [8:13] ack+dataoff, [14:16] window,
	// [18:tcpHdrLen] options (incl. urgent).
	tcp := ipHdrLen
	if !bytes.Equal(a[tcp:tcp+4], b[tcp:tcp+4]) {
		return false
	}
	if !bytes.Equal(a[tcp+8:tcp+13], b[tcp+8:tcp+13]) {
		return false
	}
	if !bytes.Equal(a[tcp+14:tcp+16], b[tcp+14:tcp+16]) {
		return false
	}
	if !bytes.Equal(a[tcp+18:], b[tcp+18:]) {
		return false
	}
	return true
}

// logSeqGaps reports same-flow seq discontinuities between consecutively created data slots. Input
// is in transmission order, so a gap is traffic this batch never contained: loss upstream of
// nebula, reorder across a flush boundary, or a retransmit (negative gap). The caller gates on
// debug level, so the map only allocates when enabled.
func (c *TCPCoalescer) logSeqGaps() {
	prevByFlow := make(map[flowKey]*coalesceSlot, len(c.slots))
	for _, s := range c.slots {
		if s.verbatim {
			continue
		}
		if prev, ok := prevByFlow[s.fk]; ok && prev.nextSeq != slotSeedSeq(s) {
			gap := int64(slotSeedSeq(s)) - int64(prev.nextSeq)
			c.l.Debug("tcp coalesce: cross-slot seq gap",
				"src", flowKeyAddr(s.fk, false),
				"dst", flowKeyAddr(s.fk, true),
				"sport", s.fk.sport,
				"dport", s.fk.dport,
				"prev_seed_seq", slotSeedSeq(prev),
				"prev_next_seq", prev.nextSeq,
				"this_seed_seq", slotSeedSeq(s),
				"gap_bytes", gap,
				"prev_seg_count", prev.numSeg,
				"prev_total_pay", prev.totalPay,
			)
		}
		prevByFlow[s.fk] = s
	}
}

// flowKeyAddr returns the src or dst address from fk as a netip.Addr for
// logging. Only used on the cold gap-log path so the netip allocation
// doesn't matter.
func flowKeyAddr(fk flowKey, dst bool) netip.Addr {
	src := fk.src
	if dst {
		src = fk.dst
	}
	if fk.isV6 {
		return netip.AddrFrom16(src)
	}
	var v4 [4]byte
	copy(v4[:], src[:4])
	return netip.AddrFrom4(v4)
}

// slotSeedSeq returns the TCP seq of the slot's seed (first segment).
// nextSeq tracks the seq just past the last appended byte; subtracting
// totalPay walks back to the seed. uint32 wraparound is the right TCP
// arithmetic so no special-casing is needed.
func slotSeedSeq(s *coalesceSlot) uint32 {
	return s.nextSeq - uint32(s.totalPay)
}

// ipv4HdrChecksum computes the IPv4 header checksum over hdr (which must
// already have its checksum field zeroed) and returns the folded/inverted
// 16-bit value to store.
func ipv4HdrChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// pseudoSumIPv4 / pseudoSumIPv6 build the L4 pseudo-header partial sum
// expected by the virtio NEEDS_CSUM kernel path: the 32-bit accumulator
// before folding. proto selects the L4 (TCP or UDP); the UDP coalescer
// reuses these helpers.
func pseudoSumIPv4(src, dst []byte, proto byte, l4Len int) uint32 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(proto)
	sum += uint32(l4Len)
	return sum
}

func pseudoSumIPv6(src, dst []byte, proto byte, l4Len int) uint32 {
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}
	sum += uint32(l4Len >> 16)
	sum += uint32(l4Len & 0xffff)
	sum += uint32(proto)
	return sum
}

// foldOnceNoInvert folds the 32-bit accumulator to 16 bits and returns it
// unchanged (no one's complement). This is what virtio NEEDS_CSUM wants in
// the L4 checksum field — the kernel will add the payload sum and invert.
func foldOnceNoInvert(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}
