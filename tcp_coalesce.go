package nebula

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/slackhq/nebula/overlay"
)

// ipProtoTCP is the IANA protocol number for TCP. Hardcoded instead of
// reaching for golang.org/x/sys/unix — that package doesn't define the
// constant on Windows, which would break cross-compiles even though this
// file runs unchanged on every platform.
const ipProtoTCP = 6

// tcpCoalesceBufSize caps total bytes per superpacket. Mirrors the kernel's
// sk_gso_max_size of ~64KiB; anything beyond this would be rejected anyway.
const tcpCoalesceBufSize = 65535

// tcpCoalesceMaxSegs caps how many segments we'll coalesce into a single
// superpacket. Keeping this well below the kernel's TSO ceiling bounds
// latency.
const tcpCoalesceMaxSegs = 64

// tcpCoalesceHdrCap is the scratch space we copy a seed's IP+TCP header
// into. IPv6 (40) + TCP with full options (60) = 100 bytes.
const tcpCoalesceHdrCap = 100

// initialSlots is the starting capacity of the slot pool. One flow per
// packet is the worst case so this matches a typical UDP recvmmsg batch.
const initialSlots = 64

// flowKey identifies a TCP flow by {src, dst, sport, dport, family}.
// Comparable, so linear scans over the slot list stay tight.
type flowKey struct {
	src, dst     [16]byte
	sport, dport uint16
	isV6         bool
}

// coalesceSlot is one entry in the coalescer's ordered event queue. When
// passthrough is true the slot holds a single borrowed packet that must be
// emitted verbatim (non-TCP, non-admissible TCP, or oversize seed). When
// passthrough is false the slot is an in-progress coalesced superpacket:
// hdrBuf is a mutable copy of the seed's IP+TCP header (we patch total
// length and pseudo-header partial at flush), and payIovs are *borrowed*
// slices from the caller's plaintext buffers — no payload is ever copied.
// The caller (listenOut) must keep those buffers alive until Flush.
type coalesceSlot struct {
	passthrough bool
	rawPkt      []byte // borrowed when passthrough

	fk       flowKey
	hdrBuf   [tcpCoalesceHdrCap]byte
	hdrLen   int
	ipHdrLen int
	isV6     bool
	gsoSize  int
	numSeg   int
	totalPay int
	nextSeq  uint32
	// psh closes the chain: set when the last-accepted segment had PSH or
	// was sub-gsoSize. No further appends after that.
	psh     bool
	payIovs [][]byte
}

// tcpCoalescer accumulates adjacent in-flow TCP data segments across
// multiple concurrent flows and emits each flow's run as a single TSO
// superpacket via overlay.GSOWriter. All output — coalesced or not — is
// deferred until Flush so arrival order is preserved on the wire. Owns
// no locks; one coalescer per TUN write queue.
type tcpCoalescer struct {
	plainW io.Writer
	gsoW   overlay.GSOWriter // nil when the queue doesn't support TSO

	// slots is the ordered event queue. Flush walks it once and emits each
	// entry as either a WriteGSO (coalesced) or a plainW.Write (passthrough).
	slots []*coalesceSlot
	// openSlots maps a flow key to its most recent non-sealed slot, so new
	// segments can extend an in-progress superpacket in O(1). Slots are
	// removed from this map when they close (PSH or short-last-segment),
	// when a non-admissible packet for that flow arrives, or in Flush.
	openSlots map[flowKey]*coalesceSlot
	pool      []*coalesceSlot // free list for reuse
}

func newTCPCoalescer(w io.Writer) *tcpCoalescer {
	c := &tcpCoalescer{
		plainW:    w,
		slots:     make([]*coalesceSlot, 0, initialSlots),
		openSlots: make(map[flowKey]*coalesceSlot, initialSlots),
		pool:      make([]*coalesceSlot, 0, initialSlots),
	}
	if gw, ok := w.(overlay.GSOWriter); ok && gw.GSOSupported() {
		c.gsoW = gw
	}
	return c
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
// regardless of whether it's admissible for coalescing. Returns ok=false
// for non-TCP or malformed input. Accepts IPv4 (no options, no fragmentation)
// and IPv6 (no extension headers).
func parseTCPBase(pkt []byte) (parsedTCP, bool) {
	var p parsedTCP
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
		if pkt[9] != ipProtoTCP {
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
		pkt = pkt[:totalLen]
	case 6:
		if len(pkt) < 40 {
			return p, false
		}
		if pkt[6] != ipProtoTCP {
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
		pkt = pkt[:40+payloadLen]
	default:
		return p, false
	}

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
	p.seq = binary.BigEndian.Uint32(pkt[p.ipHdrLen+4 : p.ipHdrLen+8])
	p.flags = pkt[p.ipHdrLen+13]
	p.fk.sport = binary.BigEndian.Uint16(pkt[p.ipHdrLen : p.ipHdrLen+2])
	p.fk.dport = binary.BigEndian.Uint16(pkt[p.ipHdrLen+2 : p.ipHdrLen+4])
	return p, true
}

// coalesceable reports whether a parsed TCP segment is eligible for
// coalescing. Accepts only ACK or ACK|PSH with a non-empty payload.
func (p parsedTCP) coalesceable() bool {
	const ack = 0x10
	const psh = 0x08
	if p.flags&^(ack|psh) != 0 || p.flags&ack == 0 {
		return false
	}
	return p.payLen > 0
}

// Add borrows pkt. The caller must keep pkt valid until the next Flush,
// whether or not the packet was coalesced — passthrough (non-admissible)
// packets are queued and written at Flush time, not synchronously.
func (c *tcpCoalescer) Add(pkt []byte) error {
	if c.gsoW == nil {
		c.addPassthrough(pkt)
		return nil
	}

	info, ok := parseTCPBase(pkt)
	if !ok {
		// Non-TCP or malformed — can't possibly collide with an open flow.
		c.addPassthrough(pkt)
		return nil
	}
	if !info.coalesceable() {
		// TCP but not admissible (SYN/FIN/RST/URG/CWR/ECE or zero-payload).
		// Seal this flow's open slot so later in-flow packets don't extend
		// it and accidentally reorder past this passthrough.
		delete(c.openSlots, info.fk)
		c.addPassthrough(pkt)
		return nil
	}

	if open := c.openSlots[info.fk]; open != nil {
		if c.canAppend(open, pkt, info) {
			c.appendPayload(open, pkt, info)
			if open.psh {
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

// Flush emits every queued event in arrival order. Coalesced slots go out
// via WriteGSO; passthrough slots go out via plainW.Write. Returns the
// first error observed; keeps draining so one bad packet doesn't hold up
// the rest. After Flush returns, borrowed payload slices may be recycled.
func (c *tcpCoalescer) Flush() error {
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
	for i := range c.slots {
		c.slots[i] = nil
	}
	c.slots = c.slots[:0]
	for k := range c.openSlots {
		delete(c.openSlots, k)
	}
	return first
}

func (c *tcpCoalescer) addPassthrough(pkt []byte) {
	s := c.take()
	s.passthrough = true
	s.rawPkt = pkt
	c.slots = append(c.slots, s)
}

func (c *tcpCoalescer) seed(pkt []byte, info parsedTCP) {
	if info.hdrLen > tcpCoalesceHdrCap || info.hdrLen+info.payLen > tcpCoalesceBufSize {
		// Pathological shape — can't fit our scratch, emit as-is.
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
	s.nextSeq = info.seq + uint32(info.payLen)
	s.psh = info.flags&0x08 != 0
	s.payIovs = append(s.payIovs[:0], pkt[info.hdrLen:info.hdrLen+info.payLen])
	c.slots = append(c.slots, s)
	if !s.psh {
		c.openSlots[info.fk] = s
	}
}

// canAppend reports whether info's packet extends the slot's seed: same
// header shape and stable contents, adjacent seq, not oversized, chain not
// closed.
func (c *tcpCoalescer) canAppend(s *coalesceSlot, pkt []byte, info parsedTCP) bool {
	if s.psh {
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
	if !headersMatch(s.hdrBuf[:s.hdrLen], pkt[:info.hdrLen], s.isV6, s.ipHdrLen) {
		return false
	}
	return true
}

func (c *tcpCoalescer) appendPayload(s *coalesceSlot, pkt []byte, info parsedTCP) {
	s.payIovs = append(s.payIovs, pkt[info.hdrLen:info.hdrLen+info.payLen])
	s.numSeg++
	s.totalPay += info.payLen
	s.nextSeq = info.seq + uint32(info.payLen)
	if info.payLen < s.gsoSize || info.flags&0x08 != 0 {
		s.psh = true
	}
}

func (c *tcpCoalescer) take() *coalesceSlot {
	if n := len(c.pool); n > 0 {
		s := c.pool[n-1]
		c.pool[n-1] = nil
		c.pool = c.pool[:n-1]
		return s
	}
	return &coalesceSlot{}
}

func (c *tcpCoalescer) release(s *coalesceSlot) {
	s.passthrough = false
	s.rawPkt = nil
	for i := range s.payIovs {
		s.payIovs[i] = nil
	}
	s.payIovs = s.payIovs[:0]
	s.numSeg = 0
	s.totalPay = 0
	s.psh = false
	c.pool = append(c.pool, s)
}

// flushSlot patches the header and calls WriteGSO. Does not remove the
// slot from c.slots.
func (c *tcpCoalescer) flushSlot(s *coalesceSlot) error {
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

	return c.gsoW.WriteGSO(hdr, s.payIovs, uint16(s.gsoSize), s.isV6, uint16(s.ipHdrLen))
}

// headersMatch compares two IP+TCP header prefixes for byte-for-byte
// equality on every field that must be identical across coalesced
// segments. Size/IPID/IPCsum/seq/flags/tcpCsum are masked out.
func headersMatch(a, b []byte, isV6 bool, ipHdrLen int) bool {
	if len(a) != len(b) {
		return false
	}
	if isV6 {
		// IPv6: bytes [0:4] = version/TC/flow-label, [6:8] = next_hdr/hop,
		// [8:40] = src+dst. Skip [4:6] payload length.
		if !bytes.Equal(a[0:4], b[0:4]) {
			return false
		}
		if !bytes.Equal(a[6:40], b[6:40]) {
			return false
		}
	} else {
		// IPv4: [0:2] version/IHL/TOS, [6:10] flags/fragoff/TTL/proto,
		// [12:20] src+dst. Skip [2:4] total len, [4:6] id, [10:12] csum.
		if !bytes.Equal(a[0:2], b[0:2]) {
			return false
		}
		if !bytes.Equal(a[6:10], b[6:10]) {
			return false
		}
		if !bytes.Equal(a[12:20], b[12:20]) {
			return false
		}
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

// pseudoSumIPv4 / pseudoSumIPv6 build the TCP pseudo-header partial sum
// expected by the virtio NEEDS_CSUM kernel path: the 32-bit accumulator
// before folding.
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
