package batch

import (
	"errors"
	"io"
	"log/slog"
)

// MultiCoalescer fans plaintext packets out to lane-specific batchers based
// on the IP/L4 protocol of the packet.
//
// Lanes are processed independently: the TCP coalescer only sees TCP, the
// UDP coalescer only sees UDP, and the passthrough lane handles everything else.
// Per-flow delivery order is preserved because a single 5-tuple only
// ever lands in one lane and each lane preserves its own slot order.
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
