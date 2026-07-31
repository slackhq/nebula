package batch

import (
	"errors"
	"io"
	"log/slog"

	"github.com/slackhq/nebula/iputil"
)

// MultiCoalescer fans plaintext packets out to lane-specific batchers based
// on the IP/L4 protocol of the packet.
//
// Lanes are processed independently: the TCP coalescer only sees TCP, the
// UDP coalescer only sees UDP, and the passthrough lane handles everything else.
// The ordering contract is per-flow DATA order: a flow's payload-bearing
// packets are never reordered relative to each other, because a single
// 5-tuple only ever lands in one lane and each lane emits its slots in
// creation order. Two shapes are deliberately allowed to be overtaken by
// later same-flow data:
//   - pure ACKs, which pass through without sealing the flow's open slot
//     (a late ACK is just a stale ACK; see TCPCoalescer.commitParsed);
//   - unparseable in-flow shapes (fragments, IP options), whose lane-level
//     addPassthrough does not close the flow's open slot either. Closing it
//     would need a full open-slot barrier (the flow key is unknown when the
//     parse fails) — an accepted tradeoff: mid-flow fragments are rare and
//     receivers reassemble regardless of arrival order.
//
// Routing still follows the flow, not the coalesceability: IPv4 fragments
// keep their L4 proto visible and IPv6 extension chains are walked to the
// terminal proto, so a flow's non-coalesceable shapes ride its lane as
// in-lane passthroughs rather than falling to the later-flushed pt lane.
//
// Cross-lane order is intentionally NOT preserved across the TCP/UDP/passthrough split.
type MultiCoalescer struct {
	tcp *TCPCoalescer
	udp *UDPCoalescer
	pt  *Passthrough
}

// NewMultiCoalescer builds a multi-lane batcher over w, based on available protocol support.
func NewMultiCoalescer(w io.Writer, l *slog.Logger) RxBatcher {
	m := &MultiCoalescer{
		pt: NewPassthrough(w),
	}
	m.tcp = NewTCPCoalescer(w, l)
	m.udp = NewUDPCoalescer(w)
	if m.tcp == nil && m.udp == nil {
		return m.pt //no offloads? Use passthrough directly.
	}
	return m
}

// IANA protocol numbers for the IPv6 extension headers
// iputil.IPv6FindUpperProtocol can step over. The set here must match what
// that walker walks: it is the hot path's cheap pre-guard, so the walk is
// only paid when it can actually make progress.
const (
	ipProtoHopByHop = 0
	ipProtoRouting  = 43
	ipProtoFragment = 44
	ipProtoAH       = 51
	ipProtoDestOpts = 60
)

// isIPv6ExtHeader reports whether nh is an extension header the terminal-
// protocol walk knows how to step over.
func isIPv6ExtHeader(nh byte) bool {
	switch nh {
	case ipProtoHopByHop, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestOpts:
		return true
	}
	return false
}

// Commit dispatches pkt to the appropriate lane based on IP version + L4 proto.
// On the success path the IP/TCP-or-UDP parse happens here once and the
// parsed struct is handed to the lane via commitParsed so the lane doesn't re-walk the header.
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
		if isIPv6ExtHeader(proto) {
			// Walk to the terminal protocol so the packet routes to its
			// flow's lane. It stays non-coalesceable — the lane's parser
			// rejects the ext-header shape and emits it as an in-lane
			// passthrough — but landing in the right lane preserves
			// per-flow order, exactly like IPv4 fragments (whose header
			// keeps the L4 proto visible) already do. Fragments are the
			// case that matters: every fragment names the flow's L4, so a
			// fragmented datagram travels with its flow's unfragmented
			// siblings instead of the passthrough lane, which flushes
			// after every coalescer lane and would emit it behind data
			// that arrived later. An unresolved walk (truncated or crafted
			// over-long chain) yields a non-transport number and falls to
			// the pt lane below.
			proto, _, _ = iputil.IPv6FindUpperProtocol(pkt)
		}
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
				m.udp.addPassthrough(pkt)
				return nil
			}
			return m.udp.commitParsed(pkt, info)
		}
	}
	return m.pt.Commit(pkt)
}

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
	return errors.Join(errs...)
}
