package batch

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/slackhq/nebula/overlay/tio"
)

// ipProtoUDP is the IANA protocol number for UDP.
const ipProtoUDP = 17

// udpCoalesceBufSize caps total bytes per UDP superpacket. Mirrors the
// kernel's gso_max_size; payloads beyond this are emitted as-is.
const udpCoalesceBufSize = 65535

// udpCoalesceMaxSegs caps how many segments we'll coalesce. Kernel UDP-GSO
// accepts up to 64 segments per skb (UDP_MAX_SEGMENTS); stay under that.
const udpCoalesceMaxSegs = 64

// udpSlot is one entry in the UDPCoalescer's ordered event queue.
type udpSlot struct {
	verbatim bool
	// rawPkt is borrowed: the whole packet for verbatim slots, the seed
	// packet for coalesce slots. A coalesce slot that never grows past one
	// segment is emitted from rawPkt so its original (already valid) L4
	// checksum ships DATA_VALID instead of making the kernel recompute it.
	// A multi-segment slot's superpacket header is rawPkt's, patched in place at flush.
	rawPkt []byte

	fk       flowKey
	hdrLen   int
	ipHdrLen int
	isV6     bool
	gsoSize  int // per-segment UDP payload length
	numSeg   int
	totalPay int
	payIovs  [][]byte
}

// UDPCoalescer accumulates adjacent in-flow UDP datagrams across multiple
// concurrent flows and emits each flow's run as a single GSO_UDP_L4 superpacket via tio.GSOWriter.
// Preserves the in-flow order of packets as they are Commit-ed
//
// Owns no locks; one coalescer per TUN write queue.
type UDPCoalescer struct {
	w         tio.GSOWriter
	slots     []*udpSlot
	openSlots map[flowKey]*udpSlot
	// lastSlot caches the most recently touched open slot; see the
	// TCPCoalescer field of the same name. Single-flow QUIC bulk is the
	// dominant USO workload, and multi-flow arrival comes in GRO runs, so
	// the fk compare beats the map's 38-byte key hash on most packets.
	// Kept in lockstep with openSlots: nil whenever the slot it pointed at
	// is removed.
	lastSlot *udpSlot
	pool     []*udpSlot
}

func NewUDPCoalescer(w io.Writer) *UDPCoalescer {
	gw, ok := tio.SupportsGSO(w, tio.GSOProtoUDP)
	if !ok {
		return nil
	}
	return &UDPCoalescer{
		w:         gw,
		slots:     make([]*udpSlot, 0, initialSlots),
		openSlots: make(map[flowKey]*udpSlot, initialSlots),
		pool:      make([]*udpSlot, 0, initialSlots),
	}
}

// parsedUDP holds the fields extracted from a single parse so later steps
// (admission, slot lookup, canAppend) don't re-walk the header.
type parsedUDP struct {
	fk       flowKey
	ipHdrLen int
	hdrLen   int // ipHdrLen + 8
	payLen   int
}

// parseAt extracts the flow key and IP/UDP offsets for a packet the dispatcher already knows is
// UDP; ipHdrLen is the upstream-resolved L4 offset (see flowKey.parseIPAt). p must be zero on
// entry and is filled in place. Returns false for malformed input or any shape that must not
// coalesce (IPv4 options/fragmentation, IPv6 extension headers).
func (p *parsedUDP) parseAt(pkt []byte, ipHdrLen int) bool {
	trimmed, ok := p.fk.parseIPAt(pkt, ipHdrLen)
	if !ok {
		return false
	}
	return p.parseTail(trimmed, ipHdrLen)
}

// parseTail layers the UDP-header parse on a validated IP prologue. pkt is the trimmed packet;
// fk's addresses are already filled.
func (p *parsedUDP) parseTail(pkt []byte, ipHdrLen int) bool {
	if len(pkt) < ipHdrLen+8 {
		return false
	}
	// UDP `length` field: must equal IP-derived length-of-UDP-header-plus-payload.
	udpLen := int(binary.BigEndian.Uint16(pkt[ipHdrLen+4 : ipHdrLen+6]))
	if udpLen < 8 || udpLen > len(pkt)-ipHdrLen {
		return false
	}
	p.ipHdrLen = ipHdrLen
	p.hdrLen = ipHdrLen + 8
	p.payLen = udpLen - 8
	p.fk.sport = binary.BigEndian.Uint16(pkt[ipHdrLen : ipHdrLen+2])
	p.fk.dport = binary.BigEndian.Uint16(pkt[ipHdrLen+2 : ipHdrLen+4])
	return true
}

// sealFlow closes fk's open chain, if any, keeping lastSlot in lockstep. The len guard skips
// hashing the 38-byte key when no chains are open.
func (c *UDPCoalescer) sealFlow(fk flowKey) {
	if len(c.openSlots) == 0 {
		return
	}
	if last := c.lastSlot; last != nil && last.fk == fk {
		c.lastSlot = nil
	}
	delete(c.openSlots, fk)
}

// commitStaged commits one staged packet dispatch routed to this lane. A shape the lane cannot
// coalesce (any fragmentation, unparseable header) seals every open chain — its flow is unknown —
// and rides the lane as an in-lane verbatim, still in transmission order.
func (c *UDPCoalescer) commitStaged(sp stagedPacket) error {
	if sp.fragAny {
		c.sealAllOpen()
		c.addVerbatim(sp.pkt)
		return nil
	}
	var info parsedUDP
	if !info.parseAt(sp.pkt, int(sp.ipHdrLen)) {
		c.sealAllOpen()
		c.addVerbatim(sp.pkt)
		return nil
	}
	return c.commitParsed(sp.pkt, &info)
}

// commitParsed commits one parsed UDP packet. The caller (dispatch, via parseAt) supplies a
// valid parse so the header is not re-walked here.
func (c *UDPCoalescer) commitParsed(pkt []byte, info *parsedUDP) error {
	// A zero-length UDP datagram (length == 8) is legal and must reach the TUN, but cannot be
	// coalesced.
	if info.payLen == 0 {
		c.sealFlow(info.fk)
		c.addVerbatim(pkt)
		return nil
	}
	// Cached-slot fast path; see the TCPCoalescer equivalent.
	var open *udpSlot
	if last := c.lastSlot; last != nil && last.fk == info.fk {
		open = last
	} else {
		open = c.openSlots[info.fk]
	}
	if open != nil {
		if c.canAppend(open, pkt, info) {
			if c.appendPayload(open, pkt, info) {
				// Chain closed (short segment): stop extending it.
				c.sealFlow(info.fk)
			} else {
				c.lastSlot = open
			}
			return nil
		}
		// Can't extend: evict it from openSlots and fall through to seed a
		// fresh slot.
		c.sealFlow(info.fk)
	}
	c.seed(pkt, info)
	return nil
}

func (c *UDPCoalescer) Flush() error {
	var first error
	for _, s := range c.slots {
		var err error
		if s.verbatim || s.numSeg == 1 {
			// A slot that never grew is byte-identical to the packet it was
			// seeded from; ship the original so its valid checksum rides the
			// DATA_VALID path instead of paying a kernel software csum.
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

// sealAllOpen closes every open coalesce chain. Called for unparseable packets: the flow key is
// unknown, so any open chain could otherwise absorb later data and emit it ahead of this packet.
func (c *UDPCoalescer) sealAllOpen() {
	clear(c.openSlots)
	c.lastSlot = nil
}

func (c *UDPCoalescer) addVerbatim(pkt []byte) {
	s := c.take()
	s.verbatim = true
	s.rawPkt = pkt
	c.slots = append(c.slots, s)
}

func (c *UDPCoalescer) seed(pkt []byte, info *parsedUDP) {
	if info.hdrLen+info.payLen > udpCoalesceBufSize {
		// Pathological shape that can't ride a superpacket; emit as-is. No chain for this flow can
		// be open here (commitParsed evicts before seeding), so sealFlow is defense in depth
		// against a stale cache entry absorbing later data.
		c.sealFlow(info.fk)
		c.addVerbatim(pkt)
		return
	}
	s := c.take()
	s.verbatim = false
	// rawPkt serves the numSeg==1 fast path in Flush, is the header source for canAppend, and is
	// the superpacket header flushSlot patches in place.
	s.rawPkt = pkt
	s.hdrLen = info.hdrLen
	s.ipHdrLen = info.ipHdrLen
	s.isV6 = info.fk.isV6
	s.fk = info.fk
	s.gsoSize = info.payLen
	s.numSeg = 1
	s.totalPay = info.payLen
	s.payIovs = append(s.payIovs[:0], pkt[info.hdrLen:info.hdrLen+info.payLen])
	c.slots = append(c.slots, s)
	c.openSlots[info.fk] = s
	c.lastSlot = s
}

// canAppend reports whether info's packet extends the slot's seed.
// Kernel UDP-GSO requires every segment except possibly the last to be
// exactly gsoSize, and the last may be shorter (≤ gsoSize).
func (c *UDPCoalescer) canAppend(s *udpSlot, pkt []byte, info *parsedUDP) bool {
	if info.hdrLen != s.hdrLen {
		return false
	}
	if s.numSeg >= udpCoalesceMaxSegs {
		return false
	}
	if info.payLen > s.gsoSize {
		return false
	}
	if s.hdrLen+s.totalPay+info.payLen > udpCoalesceBufSize {
		return false
	}
	// Header reads use rawPkt, which is never mutated before flush. A closed chain never reaches
	// here; closing removes the slot from openSlots, the only path in.
	if !s.isV6 && !ipv4CanCoalesceID(s.rawPkt, pkt, s.numSeg) {
		return false
	}
	if !udpHeadersMatch(s.rawPkt[:s.hdrLen], pkt[:info.hdrLen], s.isV6, s.ipHdrLen) {
		return false
	}
	return true
}

// appendPayload folds info's packet into s and reports whether the chain is now closed: kernel
// UDP-GSO requires every segment but the last to be exactly gsoSize, so a short segment must be
// the final one. The caller must deregister a closed slot from openSlots.
func (c *UDPCoalescer) appendPayload(s *udpSlot, pkt []byte, info *parsedUDP) bool {
	s.payIovs = append(s.payIovs, pkt[info.hdrLen:info.hdrLen+info.payLen])
	s.numSeg++
	s.totalPay += info.payLen
	return info.payLen < s.gsoSize
}

func (c *UDPCoalescer) take() *udpSlot {
	if n := len(c.pool); n > 0 {
		s := c.pool[n-1]
		c.pool[n-1] = nil
		c.pool = c.pool[:n-1]
		return s
	}
	return &udpSlot{}
}

func (c *UDPCoalescer) release(s *udpSlot) {
	// Reset every field, identity ones included; see TCPCoalescer.release.
	clear(s.payIovs)
	*s = udpSlot{payIovs: s.payIovs[:0]}
	c.pool = append(c.pool, s)
}

// flushSlot patches the IP header total length / IPv6 payload length and
// the UDP length to the *total* across all coalesced segments, then seeds
// the UDP checksum field with the pseudo-header partial (single-fold, not
// inverted) per virtio NEEDS_CSUM. The patches land in place in rawPkt; the
// slot is released right after, so nothing re-reads the patched header.
func (c *UDPCoalescer) flushSlot(s *udpSlot) error {
	hdr := s.rawPkt[:s.hdrLen]
	total := s.hdrLen + s.totalPay // full IP+UDP+all_payloads bytes
	l4Len := total - s.ipHdrLen    // total UDP (8 + sum of payloads)

	if s.isV6 {
		binary.BigEndian.PutUint16(hdr[4:6], uint16(l4Len))
	} else {
		binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
		hdr[10] = 0
		hdr[11] = 0
		binary.BigEndian.PutUint16(hdr[10:12], ipv4HdrChecksum(hdr[:s.ipHdrLen]))
	}

	// UDP length field (offset 4 inside the UDP header) = total UDP size.
	binary.BigEndian.PutUint16(hdr[s.ipHdrLen+4:s.ipHdrLen+6], uint16(l4Len))

	var psum uint32
	if s.isV6 {
		psum = pseudoSumIPv6(hdr[8:24], hdr[24:40], ipProtoUDP, l4Len)
	} else {
		psum = pseudoSumIPv4(hdr[12:16], hdr[16:20], ipProtoUDP, l4Len)
	}
	udpCsumOff := s.ipHdrLen + 6
	binary.BigEndian.PutUint16(hdr[udpCsumOff:udpCsumOff+2], foldOnceNoInvert(psum))

	return c.w.WriteGSO(hdr[:s.ipHdrLen], hdr[s.ipHdrLen:], s.payIovs, tio.GSOProtoUDP)
}

// udpHeadersMatch compares two IP+UDP header prefixes for byte-equality on
// every field that must be identical across coalesced segments
func udpHeadersMatch(a, b []byte, isV6 bool, ipHdrLen int) bool {
	if len(a) != len(b) {
		return false
	}
	if !ipHeadersMatch(a, b, isV6) {
		return false
	}
	// UDP: compare sport+dport ([0:4]). Skip length [4:6] and checksum [6:8]:
	// length varies (we rewrite at flush) and the checksum will be redone.
	udp := ipHdrLen
	return bytes.Equal(a[udp:udp+4], b[udp:udp+4])
}
