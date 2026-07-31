package batch

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"slices"

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
// When verbatim is true the slot holds a single borrowed packet that must be
// emitted verbatim (non-TCP, non-admissible TCP, or oversize seed).
// When verbatim is false the slot is an in-progress coalesced superpacket.
// hdrBuf is a mutable copy of the seed's IP+TCP header
// (we patch total length and pseudo-header partial at flush)
// payIovs are *borrowed* slices from the caller's plaintext buffers.
// The caller (listenOut) must keep those buffers alive until Flush.

const (
	verbatimFalse = iota
	// verbatimTrue means a sync-point packet, that may not be re-ordered
	verbatimTrue
	// verbatimACK packets are "passed through" without coalescing, but traffic "after" them may be pulled forward to facilitate coalescing.
	verbatimACK
)

type coalesceSlot struct {
	verbatim uint8
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
	// tsVal is the TCP timestamp of the slot's seed segment (uniform across
	// the slot: headersMatch requires byte-equal options for every append and
	// merge). Sort key only, see compareCoalesceSlots.
	tsVal uint32
	hasTS bool
	// sealed marks the chain permanently closed: the last-accepted segment had PSH or was sub-gsoSize,
	// so no append or flush-time merge may follow.
	// Distinct from eviction out of openSlots (e.g. on seq mismatch),
	// which leaves sealed=false so reorderForFlush can still merge the slot.
	sealed  bool
	payIovs [][]byte
}

func (c *coalesceSlot) isVerbatim() bool {
	return c.verbatim != verbatimFalse
}

// TCPCoalescer accumulates adjacent in-flow TCP data segments across multiple concurrent flows
// and emits each flow's run as a single TSO superpacket via tio.GSOWriter.
// All output, coalesced or not, is deferred until Flush so arrival order is preserved on the wire.
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
	options   []byte
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
	//window: 14, 15
	//csum: 16, 17
	//urg: 18, 19
	p.options = pkt[p.ipHdrLen+20 : p.ipHdrLen+p.tcpHdrLen : p.ipHdrLen+p.tcpHdrLen]
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
		c.addVerbatim(pkt)
		return nil
	}
	return c.commitParsed(pkt, info)
}

// commitParsed is the post-parse half of Commit. The caller must have
// already verified parseTCPBase succeeded (info is a valid TCP parse).
// Used by MultiCoalescer.Commit to avoid re-walking the IP/TCP header
// after the dispatcher has already done so.
func (c *TCPCoalescer) commitParsed(pkt []byte, info parsedTCP) error {
	if !info.coalesceable() {
		if info.pureAck() {
			// A bare window/ack update carries no ordering obligation toward
			// the flow's data: delivering it after later-arriving data only
			// makes it a stale ACK, which receivers ignore. Skipping the
			// evict keeps a bidirectional flow's inbound data run coalescing
			// across the peer ACKs interleaved into it — kernel GRO likewise
			// doesn't flush held data on a pure ACK.
			c.addVerbatimACK(pkt, info)
			return nil
		}
		// TCP but not admissible (SYN/FIN/RST/URG/CWR or a shape the flow
		// must observe in sequence). Seal this flow's open slot so later
		// in-flow packets don't extend it and accidentally reorder past this
		// verbatim. The len guard skips hashing the 38-byte key on
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
		// Can't extend: evict it from openSlots and fall through to seed a fresh slot.
		// The slot stays unsealed so reorderForFlush may still merge it.
		delete(c.openSlots, info.fk)
		if c.lastSlot == open {
			c.lastSlot = nil
		}
	}
	c.seed(pkt, info)
	return nil
}

func (c *TCPCoalescer) Flush() error {
	c.reorderForFlush()
	var first error
	for _, s := range c.slots {
		var err error
		if s.isVerbatim() || s.numSeg == 1 {
			// A slot that never grew (nor absorbed a merge) is byte-identical
			// to the packet it was seeded from; ship the original so its valid
			// checksum rides the DATA_VALID path instead of paying a kernel
			// software csum. appendPayload and mergeSlots only touch hdrBuf
			// once numSeg >= 2, so rawPkt is still pristine here.
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
	s.verbatim = verbatimTrue
	s.rawPkt = pkt
	c.slots = append(c.slots, s)
}

// addVerbatimACK commits a pure ACK as a verbatim slot that keeps its
// flow identity and sort keys. Unlike addVerbatim slots it does not split
// sort runs, so reorderForFlush may sort same-flow data across it (the
// contract allows data to overtake a bare ACK). A pure ACK's seq is the
// sender's snd_nxt, which orders it after all data the peer sent before it,
// and the TSval-first comparator keeps it behind any older-timestamp data.
func (c *TCPCoalescer) addVerbatimACK(pkt []byte, info parsedTCP) {
	s := c.take()
	s.verbatim = verbatimACK
	s.rawPkt = pkt
	s.fk = info.fk
	s.nextSeq = info.seq // totalPay stays 0, so slotSeedSeq yields info.seq
	s.tsVal, _, s.hasTS = parseTCPOptions(info.options)
	c.slots = append(c.slots, s)
}

func (c *TCPCoalescer) seed(pkt []byte, info parsedTCP) {
	if info.hdrLen > tcpCoalesceHdrCap || info.hdrLen+info.payLen > tcpCoalesceBufSize {
		// Pathological shape. Can't fit our scratch, emit as-is.
		c.addVerbatim(pkt)
		return
	}
	s := c.take()
	s.verbatim = verbatimFalse
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
	s.tsVal, _, s.hasTS = parseTCPOptions(info.options)
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
	s.verbatim = verbatimFalse
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
	s.tsVal = 0
	s.hasTS = false
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

// reorderForFlush neutralizes wire-side reorder that the rxOrder buffer
// couldn't catch (anything crossing a recvmmsg batch boundary).
// Without this pass a small wire reorder, counter 250 arriving in batch K when
// 200..249 are coming in batch K+1, would seed an out-of-seq slot first
// and emit it ahead of the lower-seq slot, manifesting at the inner TCP
// receiver as a much larger reorder than the wire actually had.
//
// Two phases:
//  1. Sort each verbatim-bounded segment of c.slots by (flow, seq).
//     Cross-flow ordering inside a segment isn't preserved (it never was
//     and doesn't matter for any single flow's TCP correctness).
//  2. Sweep once and merge adjacent same-flow slots whose ranges are now
//     contiguous AND whose tail is gsoSize-aligned. The tail constraint
//     matters because the kernel TSO splitter chops at gsoSize from the
//     start of the merged payload. A short segment in the middle would
//     desynchronize every later segment.
//
// Verbatim slots act as barriers: the merge check skips them on either
// side, so a SYN/FIN/RST/CWR is never reordered relative to its flow's
// data.
func (c *TCPCoalescer) reorderForFlush() {
	if len(c.slots) <= 1 {
		return
	}
	runStart := 0
	for i := 0; i <= len(c.slots); i++ {
		// Only hard verbatims (unparseable, SYN/FIN/RST/CWR, oversized)
		// split sort runs. Pure-ACK verbatims stay inside the run so
		// same-flow data separated by an interleaved ACK can still sort
		// adjacent and merge; their own sort keys keep them ordered.
		if i < len(c.slots) && c.slots[i].verbatim != verbatimTrue {
			continue
		}
		c.sortRun(c.slots[runStart:i])
		runStart = i + 1
	}
	out := c.slots[:0]
	for _, s := range c.slots {
		if n := len(out); n > 0 {
			prev := out[n-1]
			if !prev.isVerbatim() && !s.isVerbatim() && prev.fk == s.fk {
				// Same-flow neighbors after sort. If they aren't seq-
				// contiguous it's a real gap: packets the wire reordered
				// across batches, or actual loss before nebula. Log it so
				// the operator can quantify how often it happens
				if c.l.Enabled(context.Background(), slog.LevelDebug) {
					if prev.nextSeq != slotSeedSeq(s) {
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
				}

				if canMergeSlots(prev, s) {
					mergeSlots(prev, s)
					c.release(s)
					continue
				}
			}
		}
		out = append(out, s)
	}
	c.slots = out
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

// sortRun stable-sorts run by (flowKey, seedSeq) so each flow's slots
// cluster together in seq order, ready for the merge sweep. Stable so
// equal-key slots keep their original relative position (defensive — a
// duplicate seedSeq would already mean something's wrong upstream).
func (c *TCPCoalescer) sortRun(run []*coalesceSlot) {
	if len(run) <= 1 {
		return
	}
	// slices.SortStableFunc with a free, non-capturing comparator avoids the
	// reflection + closure-escape allocations that sort.SliceStable forces.
	slices.SortStableFunc(run, compareCoalesceSlots)
}

func compareCoalesceSlots(a, b *coalesceSlot) int {
	if cmp := flowKeyCompare(a.fk, b.fk); cmp != 0 {
		return cmp
	}
	// A retransmit carries a lower seq but a newer TCP timestamp than
	// in-flight original data. Emitting it first would advance the
	// receiver's ts_recent past the original's TSval, and PAWS would then
	// drop the original as an old duplicate. So order by TSval before seq:
	// TSval order approximates transmission order (which wire reordering
	// never changed), and slots whose TSvals tie still get seq-repaired below.
	// Flows without timestamps fall through to pure seq order, where PAWS cannot apply.
	// tcpSeqLess is reused for the TSval compare: RFC 7323 defines TSval
	// comparison in the same serial-number arithmetic.
	if a.hasTS && b.hasTS && a.tsVal != b.tsVal {
		if tcpSeqLess(a.tsVal, b.tsVal) {
			return -1
		}
		return 1
	}

	aSeq, bSeq := slotSeedSeq(a), slotSeedSeq(b)
	if aSeq == bSeq {
		return 0
	}
	if tcpSeqLess(aSeq, bSeq) {
		return -1
	}
	return 1
}

// parseTCPOptions attempts to locate timestamps. If it finds them, it returns tsval, secr, true. 0,0,false otherwise.
func parseTCPOptions(opts []byte) (uint32, uint32, bool) {
	const timeStampOptionSize = 1 + 1 + 4 + 4
	const timeStampOptionCode = 0x8
	const nopOptionCode = 0x1
	const eolOptionCode = 0x0
	// Inclusive bound: a timestamp ending exactly at len(opts) is the common
	// case (Linux emits NOP,NOP,TS as the whole option block). It also
	// guards opts[i+1] in every arm, since timeStampOptionSize >= 2.
	for i := 0; i+timeStampOptionSize <= len(opts); /* no increment */ {
		switch opts[i] {
		case eolOptionCode:
			// End-of-option-list: everything after is padding.
			return 0, 0, false
		case nopOptionCode:
			i++
		case timeStampOptionCode:
			// we found it!
			length := opts[i+1]
			if length != timeStampOptionSize {
				return 0, 0, false //weird, wrong option?
			}
			tsval := binary.BigEndian.Uint32(opts[i+2 : i+2+4])
			secr := binary.BigEndian.Uint32(opts[i+2+4 : i+2+4+4])
			return tsval, secr, true
		default:
			length := int(opts[i+1])
			if length < 2 {
				// Malformed: a non-NOP option shorter than its own
				// kind+length bytes would loop forever.
				return 0, 0, false
			}
			i += length
		}
	}
	return 0, 0, false
}

// slotSeedSeq returns the TCP seq of the slot's seed (first segment).
// nextSeq tracks the seq just past the last appended byte; subtracting
// totalPay walks back to the seed. uint32 wraparound is the right TCP
// arithmetic so no special-casing is needed.
func slotSeedSeq(s *coalesceSlot) uint32 {
	return s.nextSeq - uint32(s.totalPay)
}

// tcpSeqLess reports whether a precedes b in TCP serial-number arithmetic
// (RFC 1323 §2.3). The signed int32 cast turns the modular subtraction
// into the right comparison even across the 2^32 wrap.
func tcpSeqLess(a, b uint32) bool {
	return int32(a-b) < 0
}

// flowKeyCompare orders flowKeys deterministically. The exact ordering
// is irrelevant — only that same-flow slots cluster together so the
// post-sort sweep can merge contiguous pairs.
func flowKeyCompare(a, b flowKey) int {
	// Cheap scalar fields first so most non-matching keys short-circuit
	// without ever calling bytes.Compare. sport is the ephemeral port on
	// egress flows and discriminates fastest. For matching keys (same
	// flow), array equality on src/dst inlines to word-sized compares,
	// so we only pay bytes.Compare when the arrays actually differ.
	if a.sport != b.sport {
		if a.sport < b.sport {
			return -1
		}
		return 1
	}
	if a.dport != b.dport {
		if a.dport < b.dport {
			return -1
		}
		return 1
	}
	if a.dst != b.dst {
		return bytes.Compare(a.dst[:], b.dst[:])
	}
	if a.src != b.src {
		return bytes.Compare(a.src[:], b.src[:])
	}
	if a.isV6 != b.isV6 {
		if !a.isV6 {
			return -1
		}
		return 1
	}
	return 0
}

// canMergeSlots reports whether s can fold into prev as one merged TSO
// superpacket. Same flow, contiguous TCP byte range, equal gsoSize, and
// fits within the kernel TSO limits. The tail-of-prev check rejects any
// merge whose first slot ended on a sub-gsoSize segment — kernel TSO
// would split the merged skb at gsoSize boundaries from the start, so a
// short segment in the middle would corrupt every later segment. PSH and
// ECE state must agree across both slots: PSH is a semantic delimiter
// (preserving the sender's push boundary) and ECE state must be uniform
// across a window (the same rule canAppend enforces for in-flow appends).
// The IP-level ECN codepoint must also match: this check calls headersMatch
// → ipHeadersMatch, which compares the full DSCP/ECN byte, so two slots with
// differing ECN marks stay separate superpackets, each keeping its own mark.
//
// Note: a slot evicted on reorder (canAppend returned false on seq mismatch)
// stays sealed=false, so this restriction does not block the reorder-fix merge,
// only chains ended by PSH or a short tail.
func canMergeSlots(prev, s *coalesceSlot) bool {
	if prev.sealed {
		return false
	}
	if prev.fk != s.fk {
		return false
	}
	if prev.gsoSize != s.gsoSize {
		return false
	}
	if prev.nextSeq != slotSeedSeq(s) {
		return false
	}
	if prev.numSeg+s.numSeg > tcpCoalesceMaxSegs {
		return false
	}
	if prev.hdrLen+prev.totalPay+s.totalPay > tcpCoalesceBufSize {
		return false
	}
	if len(prev.payIovs[len(prev.payIovs)-1]) != prev.gsoSize {
		return false
	}
	prevFlags := prev.hdrBuf[prev.ipHdrLen+13]
	sFlags := s.hdrBuf[s.ipHdrLen+13]
	if (prevFlags^sFlags)&tcpFlagEce != 0 {
		return false
	}
	if !prev.isV6 && !ipv4CanCoalesceID(prev.hdrBuf[:], s.hdrBuf[:], prev.numSeg) {
		return false
	}
	if !headersMatch(prev.hdrBuf[:prev.hdrLen], s.hdrBuf[:s.hdrLen], prev.isV6, prev.ipHdrLen) {
		return false
	}
	return true
}

// mergeSlots folds src into dst in place: payIovs concatenated, counters
// and totals updated. The seed header's seq, gsoSize, and fk are unchanged.
// The caller must release src (it's no longer in c.slots after this call).
func mergeSlots(dst, src *coalesceSlot) {
	dst.payIovs = append(dst.payIovs, src.payIovs...)
	dst.numSeg += src.numSeg
	dst.totalPay += src.totalPay
	dst.nextSeq = src.nextSeq
	dst.sealed = src.sealed // dst is open — canMergeSlots rejects a sealed prev
	// carry PSH through
	dst.hdrBuf[dst.ipHdrLen+13] |= src.hdrBuf[src.ipHdrLen+13] & tcpFlagPsh
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
