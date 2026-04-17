package nebula

import (
	"encoding/binary"
	"io"

	"github.com/slackhq/nebula/overlay"
)

// IPPROTO_TCP is the IANA protocol number for TCP. Hardcoded instead of
// reaching for ipProtoTCP because golang.org/x/sys/unix doesn't
// define that constant on Windows, which would break cross-compiles even
// though this file runs unchanged on every platform.
const ipProtoTCP = 6

// tcpCoalesceBufSize bounds the largest coalesced superpacket we will buffer.
// Linux caps sk_gso_max_size around 64KiB; 65535 bytes covers IP hdr + TCP
// hdr + up to ~65KB of payload, which is the most the kernel's TSO can
// segment in one shot.
const tcpCoalesceBufSize = 65535

// tcpCoalesceMaxSegs caps how many segments we are willing to coalesce into
// a single superpacket regardless of byte budget. Kernel allows up to 64
// for UDP GSO and 128 for many TSO engines; stop well before either limit
// to keep latency bounded.
const tcpCoalesceMaxSegs = 64

// tcpCoalescer accumulates adjacent in-flow TCP data segments into a single
// TSO superpacket and emits them via overlay.GSOWriter in one writev. When
// a packet fails admission or fails to extend the pending flow, the
// pending superpacket is flushed and the non-matching packet is written
// through as-is. Owns no locks — one coalescer per TUN write queue.
type tcpCoalescer struct {
	plainW io.Writer
	gsoW   overlay.GSOWriter // nil when the queue doesn't support TSO

	buf      []byte
	bufLen   int  // valid bytes in buf — hdrLen plus accumulated payload
	active   bool // a seed packet is present
	numSeg   int
	gsoSize  int // payload length of each segment (= MSS of the seed)
	isV6     bool
	ipHdrLen int
	hdrLen   int    // ipHdrLen + tcpHdrLen, the offset where payload starts
	nextSeq  uint32 // expected TCP seq of the next packet to coalesce
	// psh indicates the last-accepted segment had PSH set. We accept a PSH
	// packet as the final segment but reject any further Adds after that.
	psh bool
}

func newTCPCoalescer(w io.Writer) *tcpCoalescer {
	c := &tcpCoalescer{plainW: w, buf: make([]byte, tcpCoalesceBufSize)}
	if gw, ok := w.(overlay.GSOWriter); ok && gw.GSOSupported() {
		c.gsoW = gw
	}
	return c
}

// parsedTCP holds the byte offsets / values we extract from one admission
// check so Add and canAppend don't re-parse the same header twice.
type parsedTCP struct {
	isV6      bool
	ipHdrLen  int
	tcpHdrLen int
	hdrLen    int // ipHdrLen + tcpHdrLen
	payLen    int
	seq       uint32
	flags     byte
}

// parseCoalesceable decides whether pkt is eligible for TCP coalescing. It
// accepts IPv4 (no options, DF set, no fragmentation) and IPv6 (no
// extension headers) carrying a TCP segment with flags in {ACK, ACK|PSH}
// and a non-empty payload. On success it returns the parsed offsets.
func parseCoalesceable(pkt []byte) (parsedTCP, bool) {
	var p parsedTCP
	if len(pkt) < 20 {
		return p, false
	}
	v := pkt[0] >> 4
	switch v {
	case 4:
		if len(pkt) < 20 {
			return p, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl != 20 {
			return p, false // reject IP options
		}
		if pkt[9] != ipProtoTCP {
			return p, false
		}
		// Fragment check: MF=0 and frag offset=0. Accept DF=1 or DF=0 —
		// just reject any actual fragmentation.
		fragField := binary.BigEndian.Uint16(pkt[6:8])
		if fragField&0x3fff != 0 {
			return p, false
		}
		totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
		if totalLen > len(pkt) || totalLen < ihl {
			return p, false
		}
		p.isV6 = false
		p.ipHdrLen = ihl
		pkt = pkt[:totalLen]
	case 6:
		if len(pkt) < 40 {
			return p, false
		}
		if pkt[6] != ipProtoTCP {
			return p, false // reject ext headers
		}
		payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if 40+payloadLen > len(pkt) {
			return p, false
		}
		p.isV6 = true
		p.ipHdrLen = 40
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
	flags := pkt[p.ipHdrLen+13]
	// Allow only ACK and ACK|PSH. In particular: no SYN/FIN/RST/URG/CWR/ECE.
	const ack = 0x10
	const psh = 0x08
	if flags&^(ack|psh) != 0 || flags&ack == 0 {
		return p, false
	}
	p.tcpHdrLen = tcpOff
	p.hdrLen = p.ipHdrLen + tcpOff
	p.payLen = len(pkt) - p.hdrLen
	if p.payLen <= 0 {
		return p, false
	}
	p.seq = binary.BigEndian.Uint32(pkt[p.ipHdrLen+4 : p.ipHdrLen+8])
	p.flags = flags
	return p, true
}

// Add takes a plaintext inbound packet destined for the tun. If GSO is
// unavailable or the packet isn't coalesceable, Add falls through to a
// plain Write on the underlying queue (flushing any pending superpacket
// first).
func (c *tcpCoalescer) Add(pkt []byte) error {
	if c.gsoW == nil {
		_, err := c.plainW.Write(pkt)
		return err
	}

	info, ok := parseCoalesceable(pkt)
	if !ok {
		if c.active {
			if err := c.flushLocked(); err != nil {
				return err
			}
		}
		_, err := c.plainW.Write(pkt)
		return err
	}

	if c.active {
		if c.canAppend(pkt, info) {
			c.appendPayload(pkt, info)
			if info.flags&0x08 != 0 {
				c.psh = true
			}
			return nil
		}
		if err := c.flushLocked(); err != nil {
			return err
		}
	}
	return c.seed(pkt, info)
}

// Flush emits any pending superpacket. Called by the UDP read loop at
// recvmmsg batch boundaries — "no more packets coming right now".
func (c *tcpCoalescer) Flush() error {
	if !c.active {
		return nil
	}
	return c.flushLocked()
}

func (c *tcpCoalescer) reset() {
	c.active = false
	c.bufLen = 0
	c.numSeg = 0
	c.gsoSize = 0
	c.hdrLen = 0
	c.ipHdrLen = 0
	c.nextSeq = 0
	c.psh = false
}

func (c *tcpCoalescer) seed(pkt []byte, info parsedTCP) error {
	if info.hdrLen+info.payLen > len(c.buf) {
		// Oversize single packet — flush (already done above) and passthrough.
		_, err := c.plainW.Write(pkt)
		return err
	}
	copy(c.buf, pkt[:info.hdrLen+info.payLen])
	c.active = true
	c.bufLen = info.hdrLen + info.payLen
	c.numSeg = 1
	c.gsoSize = info.payLen
	c.isV6 = info.isV6
	c.ipHdrLen = info.ipHdrLen
	c.hdrLen = info.hdrLen
	c.nextSeq = info.seq + uint32(info.payLen)
	c.psh = info.flags&0x08 != 0
	return nil
}

// canAppend reports whether info's packet extends the current seed: same
// flow, adjacent seq, payload size rule, and no-PSH-mid-chain.
func (c *tcpCoalescer) canAppend(pkt []byte, info parsedTCP) bool {
	if c.psh {
		return false // we already accepted a PSH — chain is closed
	}
	if info.isV6 != c.isV6 {
		return false
	}
	if info.hdrLen != c.hdrLen {
		return false
	}
	if info.seq != c.nextSeq {
		return false
	}
	if c.numSeg >= tcpCoalesceMaxSegs {
		return false
	}
	if c.bufLen+info.payLen > len(c.buf) {
		return false
	}
	// Every mid-chain segment must be exactly gsoSize. The final segment may
	// be shorter, but once a short segment is appended we can't add another.
	if info.payLen > c.gsoSize {
		return false
	}
	if info.payLen < c.gsoSize {
		// Will become the last segment — always OK to append, just no more.
	}
	// Compare the stable parts of the header.
	if !headersMatch(c.buf[:c.hdrLen], pkt[:info.hdrLen], c.isV6, c.ipHdrLen) {
		return false
	}
	return true
}

func (c *tcpCoalescer) appendPayload(pkt []byte, info parsedTCP) {
	copy(c.buf[c.bufLen:], pkt[info.hdrLen:info.hdrLen+info.payLen])
	c.bufLen += info.payLen
	c.numSeg++
	c.nextSeq = info.seq + uint32(info.payLen)
	// If this was a sub-gsoSize last segment, mark chain as closed.
	if info.payLen < c.gsoSize {
		c.psh = true
	}
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
		if !bytesEq(a[0:4], b[0:4]) {
			return false
		}
		if !bytesEq(a[6:40], b[6:40]) {
			return false
		}
	} else {
		// IPv4: [0:2] version/IHL/TOS, [6:10] flags/fragoff/TTL/proto,
		// [12:20] src+dst. Skip [2:4] total len, [4:6] id, [10:12] csum.
		if !bytesEq(a[0:2], b[0:2]) {
			return false
		}
		if !bytesEq(a[6:10], b[6:10]) {
			return false
		}
		if !bytesEq(a[12:20], b[12:20]) {
			return false
		}
	}
	// TCP: compare [0:4] ports, [8:13] ack+dataoff, [14:16] window,
	// [18:tcpHdrLen] options (incl. urgent).
	tcp := ipHdrLen
	if !bytesEq(a[tcp:tcp+4], b[tcp:tcp+4]) {
		return false
	}
	if !bytesEq(a[tcp+8:tcp+13], b[tcp+8:tcp+13]) {
		return false
	}
	if !bytesEq(a[tcp+14:tcp+16], b[tcp+14:tcp+16]) {
		return false
	}
	if !bytesEq(a[tcp+18:], b[tcp+18:]) {
		return false
	}
	return true
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *tcpCoalescer) flushLocked() error {
	// Guarantee the coalescer is empty on exit regardless of how we leave.
	defer c.reset()

	if c.numSeg <= 1 {
		_, err := c.plainW.Write(c.buf[:c.bufLen])
		return err
	}

	total := c.bufLen
	l4Len := total - c.ipHdrLen

	// Fix IP header length field.
	if c.isV6 {
		if l4Len > 0xffff {
			// Shouldn't happen given buffer size, but guard against it.
			return c.flushAsPerSegment()
		}
		binary.BigEndian.PutUint16(c.buf[4:6], uint16(l4Len))
	} else {
		if total > 0xffff {
			return c.flushAsPerSegment()
		}
		binary.BigEndian.PutUint16(c.buf[2:4], uint16(total))
		// Recompute IPv4 header checksum.
		c.buf[10] = 0
		c.buf[11] = 0
		binary.BigEndian.PutUint16(c.buf[10:12], ipv4HdrChecksum(c.buf[:c.ipHdrLen]))
	}

	// Write the virtio NEEDS_CSUM pseudo-header partial into the TCP csum field.
	var psum uint32
	if c.isV6 {
		psum = pseudoSumIPv6(c.buf[8:24], c.buf[24:40], ipProtoTCP, l4Len)
	} else {
		psum = pseudoSumIPv4(c.buf[12:16], c.buf[16:20], ipProtoTCP, l4Len)
	}
	tcsum := c.ipHdrLen + 16
	binary.BigEndian.PutUint16(c.buf[tcsum:tcsum+2], foldOnceNoInvert(psum))

	return c.gsoW.WriteGSO(c.buf[:total], uint16(c.gsoSize), c.isV6, uint16(c.hdrLen), uint16(c.ipHdrLen))
}

// flushAsPerSegment is a defensive fallback used if the coalesced superpacket
// somehow exceeds 16-bit length fields. It writes the packet as-is through
// the plain writer (the kernel will reject it, but that's a visible error
// rather than silent corruption).
func (c *tcpCoalescer) flushAsPerSegment() error {
	_, err := c.plainW.Write(c.buf[:c.bufLen])
	return err
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
