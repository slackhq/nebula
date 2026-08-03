package batch

import (
	"errors"
	"io"
	"log/slog"
	"slices"

	"github.com/slackhq/nebula/iputil"
)

// MultiCoalescer stages plaintext packets with their (epoch, counter) sort
// keys, and at Flush replays them in sender-transmission order into
// lane-specific batchers selected by the IP/L4 protocol of the packet.
//
// Sorting *before* the lanes see anything is what makes the ordering story
// simple: each lane consumes packets in transmission order, builds its slots
// in that order, and emits them in creation order. Wire reorder inside a
// flush batch is repaired here, before it can fragment a lane's coalesce
// chains, so the lanes carry no reorder-repair machinery of their own.
//
// The ordering contract is per-tunnel transmission order within each lane:
// a sender's packets are emitted in the order it encrypted them. Two
// qualifications:
//   - a pure TCP ACK may be overtaken by later same-flow data, because it
//     does not close the flow's open coalesce chain (a late ACK is just a
//     stale ACK; see TCPCoalescer.commitParsed);
//   - an unparseable shape (fragment, IP options) seals every open chain in
//     its lane — its flow is unknowable, so this is the only way to keep
//     later data from extending a chain that would emit ahead of it. The
//     packet then rides its lane as an in-lane passthrough, still in
//     transmission order.
//
// Routing follows the flow, not the coalesceability: IPv4 fragments keep
// their L4 proto visible and IPv6 extension chains are walked to the
// terminal proto, so a flow's non-coalesceable shapes ride its lane rather
// than falling to the later-flushed pt lane.
//
// Cross-lane order is intentionally NOT preserved across the TCP/UDP/verbatim split.
type MultiCoalescer struct {
	tcp *TCPCoalescer
	udp *UDPCoalescer
	pt  *Passthrough

	// staged holds this batch's packets and sort keys until Flush. Borrowed:
	// the caller keeps each pkt alive until Flush returns.
	staged []stagedPacket
}

type stagedPacket struct {
	pkt []byte
	key SortKey
}

// NewMultiCoalescer builds a multi-lane batcher over w, based on available
// protocol support. The staging sort applies even when no GSO lane is
// available: passthrough-only platforms still get transmission-order repair.
func NewMultiCoalescer(w io.Writer, l *slog.Logger) RxBatcher {
	m := &MultiCoalescer{
		pt:     NewPassthrough(w),
		staged: make([]stagedPacket, 0, initialSlots),
	}
	m.tcp = NewTCPCoalescer(w, l)
	m.udp = NewUDPCoalescer(w)
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

// Commit stages pkt for the next Flush. All parsing and lane dispatch is
// deferred to Flush so it runs on packets already in transmission order.
func (m *MultiCoalescer) Commit(pkt []byte, key SortKey) error {
	m.staged = append(m.staged, stagedPacket{pkt: pkt, key: key})
	return nil
}

// compareStaged orders staged packets by (epoch, counter): sender
// transmission order within a tunnel, tunnel-creation order across a
// re-handshake cutover. Keys are unique (see SortKey), so this is a total
// order and sort stability doesn't matter.
func compareStaged(a, b stagedPacket) int {
	if a.key.Epoch != b.key.Epoch {
		if a.key.Epoch < b.key.Epoch {
			return -1
		}
		return 1
	}
	if a.key.Counter == b.key.Counter {
		return 0
	}
	if a.key.Counter < b.key.Counter {
		return -1
	}
	return 1
}

// dispatch routes one packet to the appropriate lane based on IP version +
// L4 proto. On the success path the IP/TCP-or-UDP parse happens here once
// and the parsed struct is handed to the lane via commitParsed so the lane
// doesn't re-walk the header.
func (m *MultiCoalescer) dispatch(pkt []byte) error {
	if len(pkt) < 20 {
		return m.pt.enqueue(pkt)
	}
	v := pkt[0] >> 4
	var proto byte
	switch v {
	case 4:
		proto = pkt[9]
	case 6:
		if len(pkt) < 40 {
			return m.pt.enqueue(pkt)
		}
		proto = pkt[6]
		if isIPv6ExtHeader(proto) {
			// Walk to the terminal protocol so the packet routes to its flow's protocol lane.
			// This protects flow ordering.
			proto, _, _ = iputil.IPv6FindUpperProtocol(pkt)
		}
	default:
		return m.pt.enqueue(pkt)
	}
	switch proto {
	case ipProtoTCP:
		if m.tcp != nil {
			info, ok := parseTCPBase(pkt)
			if !ok {
				// Unsupported TCP shape (IP options, fragments, ...). Its flow
				// key is unknowable, so seal every open chain: dispatch runs in
				// transmission order, and sealing is what keeps later data from
				// extending a chain that would emit ahead of this packet.
				m.tcp.sealAllOpen()
				m.tcp.addVerbatim(pkt)
				return nil
			}
			return m.tcp.commitParsed(pkt, info)
		}
	case ipProtoUDP:
		if m.udp != nil {
			info, ok := parseUDP(pkt)
			if !ok {
				m.udp.sealAllOpen()
				m.udp.addVerbatim(pkt)
				return nil
			}
			return m.udp.commitParsed(pkt, info)
		}
	}
	return m.pt.enqueue(pkt)
}

// Flush sorts the staged batch into transmission order, replays it into the
// lanes, then flushes each lane.
func (m *MultiCoalescer) Flush() error {
	// Arrival order is already almost sorted (reorder is the exception, not
	// the rule), which pdqsort detects and handles in near-linear time.
	slices.SortFunc(m.staged, compareStaged)

	var errs []error
	for _, sp := range m.staged {
		if err := m.dispatch(sp.pkt); err != nil {
			errs = append(errs, err)
		}
	}
	clear(m.staged) // drop borrowed pkt refs
	m.staged = m.staged[:0]

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
