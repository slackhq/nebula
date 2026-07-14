package batch

import (
	"errors"
	"io"
	"log/slog"
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
	// arena is owned by the Multi: lanes get only its Reserve (nil Resetter)
	// and Flush resets it exactly once after every lane has drained.
	arena *Arena
}

// DefaultMultiArenaCap is the recommended arena capacity for a Multi-lane
// batcher: 64 slots × 65535 bytes ≈ 4 MiB, enough to hold one recvmmsg
// burst worth of MTU-sized packets without the arena growing.
const DefaultMultiArenaCap = initialSlots * 65535

// NewMultiCoalescer builds a multi-lane batcher. tcpEnabled lets the caller
// opt out of TCP coalescing (e.g. when the queue can't do TSO); udpEnabled
// likewise gates UDP coalescing (only enable when USO was negotiated).
// Either lane disabled redirects its traffic into the passthrough lane.
// arena is the single backing slab shared across every lane; the caller
// pre-sizes it via NewArena so the hot path never allocates.
func NewMultiCoalescer(w io.Writer, l *slog.Logger, arena *Arena, tcpEnabled, udpEnabled bool) *MultiCoalescer {
	m := &MultiCoalescer{
		pt:    NewPassthrough(w, arena.Reserve, nil),
		arena: arena,
	}
	if tcpEnabled {
		m.tcp = NewTCPCoalescer(w, l, arena.Reserve, nil)
	}
	if udpEnabled {
		m.udp = NewUDPCoalescer(w, arena.Reserve, nil)
	}
	return m
}

func (m *MultiCoalescer) Reserve(sz int) []byte {
	return m.arena.Reserve(sz)
}

// Commit dispatches pkt to the appropriate lane based on IP version + L4
// proto. Borrowed slice contract is identical to the single-lane batchers,
// pkt must remain valid until the next Flush.
//
// On the success path the IP/TCP-or-UDP parse happens here once and the
// parsed struct is handed to the lane via commitParsed so the lane doesn't
// re-walk the header.
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
				// Malformed/unsupported TCP shape (IP options, fragments, ...).
				// Handle this via passthrough support in the TCP coalescer, to attempt to preserve flow order.
				m.tcp.addPassthrough(pkt)
				return nil
			}
			return m.tcp.commitParsed(pkt, info)
		}
	case ipProtoUDP:
		if m.udp != nil {
			info, ok := parseUDP(pkt)
			if !ok {
				m.udp.addPassthrough(pkt) //we could also m.pt.Commit() here I guess?
				return nil
			}
			return m.udp.commitParsed(pkt, info)
		}
	}
	return m.pt.Commit(pkt)
}

// Flush drains every lane in a fixed order, then resets the shared arena once.
// A lane error doesn't stop the remaining lanes; the joined errors are returned.
func (m *MultiCoalescer) Flush() error {
	var errs []error
	if m.tcp != nil {
		if err := m.tcp.Flush(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.udp != nil {
		if err := m.udp.Flush(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.pt.Flush(); err != nil {
		errs = append(errs, err)
	}
	m.arena.Reset()
	return errors.Join(errs...)
}
