package batch

import (
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

// udpCoalesceHdrCap is the scratch space we copy a seed's IP+UDP header
// into. IPv6 (40) + UDP (8) = 48; round up for safety.
const udpCoalesceHdrCap = 64

// udpSlot is one entry in the UDPCoalescer's ordered event queue. Same
// passthrough-vs-coalesced shape as the TCP coalescer's slot, but no
// seq/PSH/CWR bookkeeping — UDP segments only need 5-tuple + length
// matching to coalesce.
type udpSlot struct {
	passthrough bool
	rawPkt      []byte // borrowed when passthrough

	fk       flowKey
	hdrBuf   [udpCoalesceHdrCap]byte
	hdrLen   int
	ipHdrLen int
	isV6     bool
	gsoSize  int // per-segment UDP payload length
	numSeg   int
	totalPay int
	// sealed closes the chain: set when a sub-gsoSize segment is appended
	// (kernel UDP-GSO requires every segment but the last to be exactly
	// gsoSize) or when limits are hit. No further appends after.
	sealed  bool
	payIovs [][]byte
}

// UDPCoalescer accumulates adjacent in-flow UDP datagrams across multiple
// concurrent flows and emits each flow's run as a single GSO_UDP_L4
// superpacket via tio.GSOWriter. Falls back to per-packet writes when the
// underlying writer doesn't support USO.
//
// All output — coalesced or not — is deferred until Flush so per-flow
// arrival order is preserved on the wire. Cross-flow order is NOT preserved
// across the TCP/UDP/passthrough split when this coalescer runs alongside
// others — see multi_coalesce.go. Per-flow order is preserved because a
// single 5-tuple only ever lands in one lane and each lane preserves its
// own slot order.
//
// Owns no locks; one coalescer per TUN write queue.
type UDPCoalescer struct {
	plainW io.Writer
	gsoW   tio.GSOWriter // nil when the queue can't accept GSO_UDP_L4

	slots     []*udpSlot
	openSlots map[flowKey]*udpSlot
	pool      []*udpSlot

	// arena is injected; see TCPCoalescer.arena for the contract.
	arena *Arena
}

// NewUDPCoalescer wraps w. The caller is responsible for only constructing
// this when the underlying Queue's Capabilities advertise USO; otherwise
// the kernel may reject GSO_UDP_L4 writes. If w does not implement
// tio.GSOWriter at all (single-packet Queue), the coalescer degrades to
// plain Writes — same defensive shape as the TCP coalescer.
func NewUDPCoalescer(w io.Writer, arena *Arena) *UDPCoalescer {
	c := &UDPCoalescer{
		plainW:    w,
		slots:     make([]*udpSlot, 0, initialSlots),
		openSlots: make(map[flowKey]*udpSlot, initialSlots),
		pool:      make([]*udpSlot, 0, initialSlots),
		arena:     arena,
	}
	if gw, ok := tio.SupportsGSO(w, tio.GSOProtoUDP); ok {
		c.gsoW = gw
	}
	return c
}

// parsedUDP holds the fields extracted from a single parse so later steps
// (admission, slot lookup, canAppend) don't re-walk the header.
type parsedUDP struct {
	fk       flowKey
	ipHdrLen int
	hdrLen   int // ipHdrLen + 8
	payLen   int
}

// parseUDP extracts the flow key and IP/UDP offsets for a UDP packet.
// Returns ok=false for non-UDP, malformed, or unsupported header shapes
// (IPv4 with options/fragmentation, IPv6 with extension headers).
func parseUDP(pkt []byte) (parsedUDP, bool) {
	var p parsedUDP
	ip, ok := parseIPPrologue(pkt, ipProtoUDP)
	if !ok {
		return p, false
	}
	pkt = ip.pkt
	p.fk = ip.fk
	p.ipHdrLen = ip.ipHdrLen

	if len(pkt) < p.ipHdrLen+8 {
		return p, false
	}
	p.hdrLen = p.ipHdrLen + 8
	// UDP `length` field: must equal IP-derived length-of-UDP-header-plus-payload.
	udpLen := int(binary.BigEndian.Uint16(pkt[p.ipHdrLen+4 : p.ipHdrLen+6]))
	if udpLen < 8 || udpLen > len(pkt)-p.ipHdrLen {
		return p, false
	}
	p.payLen = udpLen - 8
	p.fk.sport = binary.BigEndian.Uint16(pkt[p.ipHdrLen : p.ipHdrLen+2])
	p.fk.dport = binary.BigEndian.Uint16(pkt[p.ipHdrLen+2 : p.ipHdrLen+4])
	return p, true
}

func (c *UDPCoalescer) Reserve(sz int) []byte {
	return c.arena.Reserve(sz)
}

// Commit borrows pkt. The caller must keep pkt valid until the next Flush.
func (c *UDPCoalescer) Commit(pkt []byte) error {
	if c.gsoW == nil {
		c.addPassthrough(pkt)
		return nil
	}
	info, ok := parseUDP(pkt)
	if !ok {
		c.addPassthrough(pkt)
		return nil
	}
	return c.commitParsed(pkt, info)
}

// commitParsed is the post-parse half of Commit. The caller must have
// already verified parseUDP succeeded. Used by MultiCoalescer.Commit to
// avoid re-walking the IP/UDP header.
func (c *UDPCoalescer) commitParsed(pkt []byte, info parsedUDP) error {
	if c.gsoW == nil {
		c.addPassthrough(pkt)
		return nil
	}
	// A zero-length UDP datagram (UDP `length` == 8) is legal and must still
	// reach the TUN, but it can't be coalesced: a GSO slot would store an
	// empty payload iovec and the kernel has nothing to segment. Seal any
	// open chain for this flow (so a later, non-empty datagram seeds fresh
	// *after* this one and per-flow arrival order is preserved) and deliver
	// it as a plain single datagram.
	if info.payLen == 0 {
		delete(c.openSlots, info.fk)
		c.addPassthrough(pkt)
		return nil
	}
	if open := c.openSlots[info.fk]; open != nil {
		if c.canAppend(open, pkt, info) {
			c.appendPayload(open, pkt, info)
			if open.sealed {
				delete(c.openSlots, info.fk)
			}
			return nil
		}
		// Can't extend — seal it and fall through to seed a fresh slot.
		delete(c.openSlots, info.fk)
	}
	c.seed(pkt, info)
	return nil
}

func (c *UDPCoalescer) Flush() error {
	var first error
	for _, s := range c.slots {
		var err error
		if s.passthrough {
			_, err = c.plainW.Write(s.rawPkt)
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
	c.arena.Reset()
	return first
}

func (c *UDPCoalescer) addPassthrough(pkt []byte) {
	s := c.take()
	s.passthrough = true
	s.rawPkt = pkt
	c.slots = append(c.slots, s)
}

func (c *UDPCoalescer) seed(pkt []byte, info parsedUDP) {
	if info.hdrLen > udpCoalesceHdrCap || info.hdrLen+info.payLen > udpCoalesceBufSize {
		c.addPassthrough(pkt)
		return
	}
	s := c.take()
	s.passthrough = false
	s.rawPkt = nil
	copy(s.hdrBuf[:], pkt[:info.hdrLen])
	s.hdrLen = info.hdrLen
	s.ipHdrLen = info.ipHdrLen
	s.isV6 = info.fk.isV6
	s.fk = info.fk
	s.gsoSize = info.payLen
	s.numSeg = 1
	s.totalPay = info.payLen
	s.sealed = false
	s.payIovs = append(s.payIovs[:0], pkt[info.hdrLen:info.hdrLen+info.payLen])
	c.slots = append(c.slots, s)
	c.openSlots[info.fk] = s
}

// canAppend reports whether info's packet extends the slot's seed.
// Kernel UDP-GSO requires every segment except possibly the last to be
// exactly gsoSize, and the last may be shorter (≤ gsoSize).
func (c *UDPCoalescer) canAppend(s *udpSlot, pkt []byte, info parsedUDP) bool {
	if s.sealed {
		return false
	}
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
	if !udpHeadersMatch(s.hdrBuf[:s.hdrLen], pkt[:info.hdrLen], s.isV6, s.ipHdrLen) {
		return false
	}
	return true
}

func (c *UDPCoalescer) appendPayload(s *udpSlot, pkt []byte, info parsedUDP) {
	s.payIovs = append(s.payIovs, pkt[info.hdrLen:info.hdrLen+info.payLen])
	s.numSeg++
	s.totalPay += info.payLen
	if info.payLen < s.gsoSize {
		// Last-segment-can-be-shorter: this seals the chain.
		s.sealed = true
	}
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
	s.passthrough = false
	s.rawPkt = nil
	clear(s.payIovs)
	s.payIovs = s.payIovs[:0]
	s.numSeg = 0
	s.totalPay = 0
	s.sealed = false
	c.pool = append(c.pool, s)
}

// flushSlot patches the IP header total length / IPv6 payload length and
// the UDP length to the *total* across all coalesced segments, then seeds
// the UDP checksum field with the pseudo-header partial (single-fold, not
// inverted) per virtio NEEDS_CSUM. The kernel's ip_rcv_core (v4) and
// ip6_rcv_core (v6) trim the skb to those length fields, so per-segment
// values would silently drop everything but the first segment. The kernel
// then walks each segment in __udp_gso_segment, recomputing per-segment
// uh->len / iph->tot_len / IPv6 plen and adjusting the checksum via
// `check = csum16_add(csum16_sub(uh->check, uh->len), newlen)` — meaning
// our seed's uh->check must be consistent with the seed's uh->len, which
// is what passing the total to both pseudoSum and the UDP length field
// guarantees.
func (c *UDPCoalescer) flushSlot(s *udpSlot) error {
	hdr := s.hdrBuf[:s.hdrLen]
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

	return c.gsoW.WriteGSO(hdr[:s.ipHdrLen], hdr[s.ipHdrLen:], s.payIovs, tio.GSOProtoUDP)
}

// udpHeadersMatch compares two IP+UDP header prefixes for byte-equality on
// every field that must be identical across coalesced segments. Length
// fields are masked out (flushSlot rewrites them), but the IP-level ECN
// codepoint is compared (via ipHeadersMatch) so segments with differing ECN
// don't coalesce, matching kernel GRO.
func udpHeadersMatch(a, b []byte, isV6 bool, ipHdrLen int) bool {
	if len(a) != len(b) {
		return false
	}
	if !ipHeadersMatch(a, b, isV6) {
		return false
	}
	// UDP: compare sport+dport ([0:4]). Skip length [4:6] and checksum [6:8] —
	// length varies (we rewrite at flush) and the checksum will be redone.
	udp := ipHdrLen
	if a[udp] != b[udp] || a[udp+1] != b[udp+1] || a[udp+2] != b[udp+2] || a[udp+3] != b[udp+3] {
		return false
	}
	return true
}
