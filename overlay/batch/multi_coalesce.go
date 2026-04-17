package batch

import (
	"io"
)

// MultiCoalescer fans plaintext packets out to lane-specific batchers based
// on the IP/L4 protocol of the packet, sharing a single Reserve arena
// across lanes so the caller's allocation pattern is unchanged.
//
// Lanes are processed independently: the TCP coalescer only sees TCP, the
// UDP coalescer only sees UDP, and the passthrough lane handles everything
// else. Per-flow arrival order is preserved because a single 5-tuple only
// ever lands in one lane and each lane preserves its own slot order.
//
// Cross-lane order is NOT preserved across the TCP/UDP/passthrough split.
// This is acceptable because the carrier-side recvmmsg path already
// stable-sorts by (peer, message counter) before delivering plaintext
// here, so replay-window invariants are unaffected, and apps observe
// correct per-flow ordering — which is all the IP layer guarantees anyway.
// Do not "fix" this by interleaving lane outputs at flush time; that
// negates the entire point of coalescing (each lane needs to see runs of
// adjacent same-flow packets to coalesce them).
type MultiCoalescer struct {
	tcp *TCPCoalescer
	udp *UDPCoalescer
	pt  *Passthrough

	// arena shared across all lanes so a single Reserve grows one backing
	// slice; lane Commit calls borrow into this same arena.
	backing []byte
}

// NewMultiCoalescer builds a multi-lane batcher. tcpEnabled lets the caller
// opt out of TCP coalescing (e.g. when the queue can't do TSO); udpEnabled
// likewise gates UDP coalescing (only enable when USO was negotiated).
// Either lane disabled redirects its traffic into the passthrough lane.
func NewMultiCoalescer(w io.Writer, tcpEnabled, udpEnabled bool) *MultiCoalescer {
	m := &MultiCoalescer{
		pt:      NewPassthrough(w),
		backing: make([]byte, 0, initialSlots*65535),
	}
	if tcpEnabled {
		m.tcp = NewTCPCoalescer(w)
	}
	if udpEnabled {
		m.udp = NewUDPCoalescer(w)
	}
	return m
}

func (m *MultiCoalescer) Reserve(sz int) []byte {
	if len(m.backing)+sz > cap(m.backing) {
		newCap := max(cap(m.backing)*2, sz)
		m.backing = make([]byte, 0, newCap)
	}
	start := len(m.backing)
	m.backing = m.backing[:start+sz]
	return m.backing[start : start+sz : start+sz]
}

// Commit dispatches pkt to the appropriate lane based on IP version + L4
// proto. Borrowed slice contract is identical to the single-lane batchers
// — pkt must remain valid until the next Flush.
//
// On the success path the IP/TCP-or-UDP parse happens here once and the
// parsed struct is handed to the lane via commitParsed so the lane doesn't
// re-walk the header. On a parse failure we fall through to the lane's
// public Commit, which re-runs the parse before passthrough — that path
// only fires for malformed/unsupported packets so the duplicated parse is
// not on the hot path. The lane's public Commit still works for direct
// callers.
func (m *MultiCoalescer) Commit(pkt []byte) error {
	if len(pkt) < 20 {
		return m.pt.Commit(pkt)
	}
	v := pkt[0] >> 4
	var proto byte
	switch v {
	case 4:
		proto = pkt[9]
	case 6:
		if len(pkt) < 40 {
			return m.pt.Commit(pkt)
		}
		proto = pkt[6]
	default:
		return m.pt.Commit(pkt)
	}
	switch proto {
	case ipProtoTCP:
		if m.tcp != nil {
			info, ok := parseTCPBase(pkt)
			if !ok {
				// Malformed/unsupported TCP shape (IP options, fragments, ...)
				// — the TCP lane handles this as passthrough.
				return m.tcp.Commit(pkt)
			}
			return m.tcp.commitParsed(pkt, info)
		}
	case ipProtoUDP:
		if m.udp != nil {
			info, ok := parseUDP(pkt)
			if !ok {
				return m.udp.Commit(pkt)
			}
			return m.udp.commitParsed(pkt, info)
		}
	}
	return m.pt.Commit(pkt)
}

// Flush drains every lane in a fixed order: TCP, UDP, passthrough. Errors
// from a lane do not stop subsequent lanes from flushing — we keep
// draining and return the first observed error so a single bad packet
// doesn't strand the others.
func (m *MultiCoalescer) Flush() error {
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	if m.tcp != nil {
		keep(m.tcp.Flush())
	}
	if m.udp != nil {
		keep(m.udp.Flush())
	}
	keep(m.pt.Flush())
	m.backing = m.backing[:0]
	return first
}
