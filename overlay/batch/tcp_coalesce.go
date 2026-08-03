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

// coalesceSlot is one entry in the coalescer's ordered event queue.
// When verbatim is true the slot holds a single borrowed packet that is
// emitted as-is (pure ACK, non-admissible TCP, unparseable, or oversize seed).
// When verbatim is false the slot is an in-progress coalesced superpacket.
// hdrBuf is a mutable copy of the seed's IP+TCP header
// (we patch total length and pseudo-header partial at flush)
// payIovs are *borrowed* slices from the caller's plaintext buffers.
// The caller (listenOut) must keep those buffers alive until Flush.
type coalesceSlot struct {
	verbatim bool
	// rawPkt is borrowed: the whole packet for verbatim slots, the seed
	// packet for coalesce slots. A coalesce slot that never grows past one
	// segment is emitted from rawPkt so its original (already valid) L4
	// checksum ships DATA_VALID instead of making the kernel recompute it.
	rawPkt []byte

	fk       flowKey
	hdrBuf   [tcpCoalesceHdrCap]byte
	hdrLen   int
	ipHdrLen int
	isV6     bool
	gsoSize  int
	numSeg   int
	totalPay int
	nextSeq  uint32
	// sealed marks the chain permanently closed: the last-accepted segment
	// had PSH or was sub-gsoSize, so no append may follow. Belt-and-
	// suspenders with removal from openSlots, which is what actually stops
	// the append paths from finding the slot.
	sealed  bool
	payIovs [][]byte
}

// TCPCoalescer accumulates adjacent in-flow TCP data segments across multiple concurrent flows
// and emits each flow's run as a single TSO superpacket via tio.GSOWriter.
// It expects its input in sender-transmission order (MultiCoalescer sorts the
// staged batch by (epoch, counter) before dispatching here) and emits slots in
// creation order, which therefore reproduces transmission order — modulo the
// pure-ACK allowance in commitParsed.
// Owns no locks; one coalescer per TUN write queue.
type TCPCoalescer struct {
	w tio.GSOWriter

	// slots is the ordered event queue. Flush walks it once and emits each
	// entry as either a WriteGSO (coalesced) or a w.Write (verbatim).
	slots []*coalesceSlot
	// openSlots maps a flow key to its most recent non-sealed slot, so new
	// segments can extend an in-progress superpacket in O(1). Slots are
	// removed from this map when they close (PSH or short-last-segment),
	// when a non-admissible packet for that flow arrives, or in Flush.
	openSlots map[flowKey]*coalesceSlot
	// lastSlot caches the most recently touched open slot. Bulk traffic
	// arrives in same-flow runs (single-flow steady state, or GRO bursts
	// under multi-flow), so comparing the incoming key against the cached
	// slot's own fk lets the hot path skip the map lookup (and the aeshash
	// of a 38-byte key) for the length of each run.
	// Kept in lockstep with openSlots: nil whenever the slot it pointed
	// at is removed/sealed.
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
	fk        flowKey
	ipHdrLen  int
	tcpHdrLen int
	hdrLen    int
	payLen    int
	seq       uint32
	flags     byte
}

// parseTCPBase extracts the flow key and IP/TCP offsets for any TCP packet,
// regardless of whether it's admissible for coalescing. Returns ok=false for non-TCP or malformed input.
// Accepts IPv4 (no options or fragmentation) and IPv6 (no extension headers).
func parseTCPBase(pkt []byte) (parsedTCP, bool) {
	var p parsedTCP
	ip, ok := parseIPPrologue(pkt, ipProtoTCP)
	if !ok {
		return p, false
	}
	pkt = ip.pkt
	p.fk = ip.fk
	p.ipHdrLen = ip.ipHdrLen

	if len(pkt) < p.ipHdrLen+20 {
		return p, false
	}
	tcpOff := int(pkt[p.ipHdrLen+12]>>4) * 4
	if tcpOff < 20 || tcpOff > 60 {
		return p, false
	}
	if len(pkt) < p.ipHdrLen+tcpOff {
		return p, false
	}
	p.tcpHdrLen = tcpOff
	p.hdrLen = p.ipHdrLen + tcpOff
	p.payLen = len(pkt) - p.hdrLen
	p.fk.sport = binary.BigEndian.Uint16(pkt[p.ipHdrLen : p.ipHdrLen+2])
	p.fk.dport = binary.BigEndian.Uint16(pkt[p.ipHdrLen+2 : p.ipHdrLen+4])
	p.seq = binary.BigEndian.Uint32(pkt[p.ipHdrLen+4 : p.ipHdrLen+8])
	p.flags = pkt[p.ipHdrLen+13]
	return p, true
}

// TCP flag bits (byte 13 of the TCP header). Only the bits actually consulted
// by the coalescer are named; FIN/SYN/RST/URG/CWR are rejected via the
// negative mask in coalesceable, not by name.
const (
	tcpFlagPsh = 0x08
	tcpFlagAck = 0x10
	tcpFlagEce = 0x40
)

// coalesceable reports whether a parsed TCP segment is eligible for
// coalescing. Accepts ACK, ACK|PSH, ACK|ECE, ACK|PSH|ECE with a
// non-empty payload. CWR is excluded because it marks a one-shot
// congestion-window-reduced transition the receiver must observe at a
// segment boundary.
func (p parsedTCP) coalesceable() bool {
	if p.flags&tcpFlagAck == 0 {
		return false
	}
	if p.flags&^(tcpFlagAck|tcpFlagPsh|tcpFlagEce) != 0 {
		return false
	}
	return p.payLen > 0
}

// pureAck reports whether a parsed segment is a bare acknowledgment: no
// payload and nothing beyond ACK|PSH|ECE in the flags. These are the only
// non-coalesceable shape that may safely pass through WITHOUT sealing the
// flow's open slot — a late-delivered stale ACK is ignored by the receiver,
// whereas SYN/FIN/RST/CWR mark transitions the flow must observe in order.
func (p parsedTCP) pureAck() bool {
	return p.payLen == 0 &&
		p.flags&tcpFlagAck != 0 &&
		p.flags&^(tcpFlagAck|tcpFlagPsh|tcpFlagEce) == 0
}

func (c *TCPCoalescer) Commit(pkt []byte) error {
	info, ok := parseTCPBase(pkt)
	if !ok {
		// Unparseable shape: flow key unknowable, so seal every open chain to
		// keep later data from extending a chain that would emit ahead of it.
		c.sealAllOpen()
		c.addVerbatim(pkt)
		return nil
	}
	return c.commitParsed(pkt, info)
}

// sealAllOpen closes every open coalesce chain: nothing committed after this
// call can extend a slot created before it. Called when an unparseable packet
// arrives — its flow is unknown, so any open chain might be the one whose
// later data would otherwise leapfrog it.
func (c *TCPCoalescer) sealAllOpen() {
	clear(c.openSlots)
	c.lastSlot = nil
}

// commitParsed is the post-parse half of Commit. The caller must have
// already verified parseTCPBase succeeded (info is a valid TCP parse).
// Used by MultiCoalescer.Commit to avoid re-walking the IP/TCP header
// after the dispatcher has already done so.
func (c *TCPCoalescer) commitParsed(pkt []byte, info parsedTCP) error {
	if !info.coalesceable() {
		if info.pureAck() {
			// A bare window/ack update carries no ordering obligation toward
			// the flow's data: delivering it after later-transmitted data only
			// makes it a stale ACK, which receivers ignore. Skipping the
			// evict keeps a bidirectional flow's inbound data run coalescing
			// across the peer ACKs interleaved into it — kernel GRO likewise
			// doesn't flush held data on a pure ACK. This is the one place
			// emission can deviate from transmission order.
			c.addVerbatim(pkt)
			return nil
		}
		// TCP but not admissible (SYN/FIN/RST/URG/CWR or a shape the flow
		// must observe in sequence). Seal this flow's open slot so later
		// in-flow packets don't extend it and emit ahead of this verbatim;
		// with input in transmission order that pins the verbatim's exact
		// in-flow position. The len guard skips hashing the 38-byte key on
		// ack-dominant queues, where the map is almost always empty.
		if len(c.openSlots) != 0 {
			if last := c.lastSlot; last != nil && last.fk == info.fk {
				c.lastSlot = nil
			}
			delete(c.openSlots, info.fk)
		}
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
			c.appendPayload(open, pkt, info)
			if open.sealed {
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
			// A slot that never grew (nor absorbed a merge) is byte-identical
			// to the packet it was seeded from; ship the original so its valid
			// checksum rides the DATA_VALID path instead of paying a kernel
			// software csum. appendPayload only touches hdrBuf once
			// numSeg >= 2, so rawPkt is still pristine here.
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

func (c *TCPCoalescer) seed(pkt []byte, info parsedTCP) {
	if info.hdrLen > tcpCoalesceHdrCap || info.hdrLen+info.payLen > tcpCoalesceBufSize {
		// Pathological shape. Can't fit our scratch, emit as-is.
		c.addVerbatim(pkt)
		return
	}
	s := c.take()
	s.verbatim = false
	s.rawPkt = pkt // kept for the numSeg==1 fast path in Flush
	copy(s.hdrBuf[:], pkt[:info.hdrLen])
	s.hdrLen = info.hdrLen
	s.ipHdrLen = info.ipHdrLen
	s.isV6 = info.fk.isV6
	s.fk = info.fk
	s.gsoSize = info.payLen
	s.numSeg = 1
	s.totalPay = info.payLen
	s.nextSeq = info.seq + uint32(info.payLen)
	s.sealed = info.flags&tcpFlagPsh != 0
	s.payIovs = append(s.payIovs[:0], pkt[info.hdrLen:info.hdrLen+info.payLen])
	c.slots = append(c.slots, s)
	if !s.sealed {
		c.openSlots[info.fk] = s
		c.lastSlot = s
	} else if last := c.lastSlot; last != nil && last.fk == info.fk {
		// PSH-on-seed seals the slot immediately. Any prior cached open
		// slot for this flow has just been sealed-and-replaced by this
		// verbatim-shaped seed, so drop the cache too.
		c.lastSlot = nil
	}
}

// canAppend reports whether info's packet extends the slot's seed: same
// header shape and stable contents, adjacent seq, not oversized, chain not closed.
func (c *TCPCoalescer) canAppend(s *coalesceSlot, pkt []byte, info parsedTCP) bool {
	if s.sealed {
		return false
	}
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
	seedFlags := s.hdrBuf[s.ipHdrLen+13]
	if (seedFlags^info.flags)&tcpFlagEce != 0 {
		return false
	}
	if !s.isV6 && !ipv4CanCoalesceID(s.hdrBuf[:], pkt, s.numSeg) {
		return false
	}
	if !headersMatch(s.hdrBuf[:s.hdrLen], pkt[:info.hdrLen], s.isV6, s.ipHdrLen) {
		return false
	}
	return true
}

func (c *TCPCoalescer) appendPayload(s *coalesceSlot, pkt []byte, info parsedTCP) {
	s.payIovs = append(s.payIovs, pkt[info.hdrLen:info.hdrLen+info.payLen])
	s.numSeg++
	s.totalPay += info.payLen
	s.nextSeq = info.seq + uint32(info.payLen)
	if info.flags&tcpFlagPsh != 0 {
		// Propagate PSH into the seed header so kernel TSO sets it on the
		// last segment. Without this the sender's push signal is dropped.
		s.hdrBuf[s.ipHdrLen+13] |= tcpFlagPsh
	}
	if info.payLen < s.gsoSize || info.flags&tcpFlagPsh != 0 {
		s.sealed = true
	}
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
	s.sealed = false
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

// logSeqGaps reports same-flow seq discontinuities between consecutively
// created data slots. Input arrives in transmission order (MultiCoalescer
// sorts by (epoch, counter) before dispatch), so a gap here is traffic this
// batch never contained: loss upstream of nebula, a reorder spanning a flush
// boundary (which no intra-batch mechanism can repair), or a retransmit
// (negative gap). Logged so the operator can quantify how often that happens.
// The caller gates on debug level, so the map only allocates when asked for.
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
