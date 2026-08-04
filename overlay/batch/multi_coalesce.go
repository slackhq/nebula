package batch

import (
	"cmp"
	"errors"
	"io"
	"log/slog"
	"slices"

	"github.com/slackhq/nebula/firewall"
)

// MultiCoalescer stages plaintext packets with their (epoch, counter) sort keys and, at Flush,
// replays them in sender-transmission order into lane-specific batchers selected by L4 protocol.
//
// Sorting before dispatch keeps the ordering story simple: each lane consumes packets in
// transmission order, builds slots in that order, and emits them in creation order. Wire reorder
// inside a flush batch is repaired here, before it can fragment a lane's coalesce chains, so the
// lanes carry no reorder-repair machinery.
//
// The contract is per-tunnel transmission order within each lane, with two exceptions: a pure TCP
// ACK may be overtaken by later same-flow data (it does not close the flow's open chain; a late
// ACK is just a stale ACK), and an unparseable shape seals every open chain in its lane (its flow
// is unknown) and rides the lane as an in-lane verbatim, still in transmission order. Routing
// follows the flow: a flow's non-coalesceable shapes ride its protocol lane rather than falling
// to the later-flushed pt lane.
//
// Cross-lane order (TCP vs UDP vs everything else) is not preserved.
type MultiCoalescer struct {
	tcp *TCPCoalescer
	udp *UDPCoalescer
	pt  *Passthrough

	// staged holds this batch's packets and sort keys until Flush. Borrowed: the caller keeps
	// each pkt alive until Flush returns.
	staged []stagedPacket
}

// stagedPacket carries the scalars dispatch needs from the firewall's ParsedPacket, copied by
// value: pp is reused by the caller per packet and must not be retained past Commit.
type stagedPacket struct {
	pkt      []byte
	key      SortKey
	proto    byte
	fragAny  bool
	ipHdrLen uint16
}

// NewMultiCoalescer builds a multi-lane batcher over w, based on available protocol support. The
// staging sort applies even when no GSO lane is available: passthrough-only platforms still get
// transmission-order repair.
func NewMultiCoalescer(w io.Writer, l *slog.Logger) *MultiCoalescer {
	m := &MultiCoalescer{
		pt:     NewPassthrough(w),
		staged: make([]stagedPacket, 0, initialSlots),
	}
	m.tcp = NewTCPCoalescer(w, l)
	m.udp = NewUDPCoalescer(w)
	return m
}

// Commit stages pkt for the next Flush; dispatch is deferred so it runs on packets already in
// transmission order. key carries the packet's tunnel epoch and message counter. pkt is borrowed:
// the caller must keep it valid until the next Flush and not re-use it. pp is the firewall's
// parse of pkt and is borrowed only for this call, so the fields dispatch needs are copied here.
func (m *MultiCoalescer) Commit(pkt []byte, key SortKey, pp *firewall.ParsedPacket) error {
	m.staged = append(m.staged, stagedPacket{
		pkt:      pkt,
		key:      key,
		proto:    pp.Protocol,
		fragAny:  pp.FragAny,
		ipHdrLen: uint16(pp.IPHdrLen),
	})
	return nil
}

// compareStaged orders staged packets by (epoch, counter)
func compareStaged(a, b stagedPacket) int {
	if c := cmp.Compare(a.key.Epoch, b.key.Epoch); c != 0 {
		return c
	}
	return cmp.Compare(a.key.Counter, b.key.Counter)
}

// dispatch routes one staged packet to its lane.
// The protocol and L4 offset come from the firewall's parse of the same packet.
// Any shape a lane can't coalesce seals every open chain in its lane
func (m *MultiCoalescer) dispatch(sp stagedPacket) error {
	switch sp.proto {
	case ipProtoTCP:
		if m.tcp != nil {
			if sp.fragAny {
				m.tcp.sealAllOpen()
				m.tcp.addVerbatim(sp.pkt)
				return nil
			}
			info, ok := parseTCPAt(sp.pkt, int(sp.ipHdrLen))
			if !ok {
				m.tcp.sealAllOpen()
				m.tcp.addVerbatim(sp.pkt)
				return nil
			}
			return m.tcp.commitParsed(sp.pkt, info)
		}
	case ipProtoUDP:
		if m.udp != nil {
			if sp.fragAny {
				m.udp.sealAllOpen()
				m.udp.addVerbatim(sp.pkt)
				return nil
			}
			info, ok := parseUDPAt(sp.pkt, int(sp.ipHdrLen))
			if !ok {
				m.udp.sealAllOpen()
				m.udp.addVerbatim(sp.pkt)
				return nil
			}
			return m.udp.commitParsed(sp.pkt, info)
		}
	}
	return m.pt.enqueue(sp.pkt)
}

// Flush sorts the staged batch into transmission order, replays it into the lanes, then flushes each lane.
// Drains everything and returns the joined errors; one bad packet does not hold up the rest.
// After Flush returns, committed payload slices may be recycled.
func (m *MultiCoalescer) Flush() error {
	// Arrival order is already almost sorted (reorder is the exception), which pdqsort detects
	// and handles in near-linear time.
	slices.SortFunc(m.staged, compareStaged)

	var errs []error
	for _, sp := range m.staged {
		if err := m.dispatch(sp); err != nil {
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
