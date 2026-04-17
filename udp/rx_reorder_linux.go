//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"cmp"
	"net/netip"
	"slices"
)

// rxSegment is one nebula packet pulled out of a recvmmsg entry — either a
// lone datagram or one segment of a GRO superpacket. cnt is the big-endian
// uint64 message counter at bytes [8:16] of the nebula header; 0 if the
// segment is too short to contain a header. ecn is the 2-bit IP-level ECN
// codepoint stamped on the carrier (one value per slot, since GRO requires
// equal ECN across coalesced datagrams).
type rxSegment struct {
	src netip.AddrPort
	cnt uint64
	buf []byte
	ecn byte
}

// rxReorderBuffer accumulates one recvmmsg batch worth of segments,
// splits any GRO superpackets at gso_size boundaries, stable-sorts by
// (src, port, counter), then delivers in order. The reorder distance is
// bounded by len(buf), which the caller sizes to stay well within the
// receiver's ReplayWindow so older arrivals are not rejected as replays.
type rxReorderBuffer struct {
	buf []rxSegment
}

func newRxReorderBuffer(initialCap int) *rxReorderBuffer {
	return &rxReorderBuffer{buf: make([]rxSegment, 0, initialCap)}
}

// reset prepares the buffer for the next recvmmsg batch.
func (r *rxReorderBuffer) reset() { r.buf = r.buf[:0] }

// addEntry expands one recvmmsg slot into rxSegments. When segSize <= 0 or
// segSize >= len(payload) the payload is appended as a single segment;
// otherwise the kernel-coalesced GRO superpacket is split at segSize
// boundaries (the kernel guarantees every segment is exactly segSize bytes
// except for the final one, which may be short). ecn applies uniformly to
// every produced segment because GRO requires equal ECN across coalesced
// datagrams.
func (r *rxReorderBuffer) addEntry(from netip.AddrPort, payload []byte, segSize int, ecn byte) {
	if segSize <= 0 || segSize >= len(payload) {
		r.buf = append(r.buf, rxSegment{from, headerCounter(payload), payload, ecn})
		return
	}
	for off := 0; off < len(payload); off += segSize {
		end := off + segSize
		if end > len(payload) {
			end = len(payload)
		}
		seg := payload[off:end]
		r.buf = append(r.buf, rxSegment{from, headerCounter(seg), seg, ecn})
	}
}

// sortStable orders the accumulated segments by (src addr, src port,
// counter). Same-source segments are reordered into counter order;
// cross-source relative order is determined by a stable address compare so
// the sort is total and predictable.
func (r *rxReorderBuffer) sortStable() {
	slices.SortStableFunc(r.buf, func(a, b rxSegment) int {
		if c := a.src.Addr().Compare(b.src.Addr()); c != 0 {
			return c
		}
		if c := cmp.Compare(a.src.Port(), b.src.Port()); c != 0 {
			return c
		}
		return cmp.Compare(a.cnt, b.cnt)
	})
}

// deliver invokes fn once per segment in sorted order, then nils the
// per-entry buf reference so the next batch's append doesn't alias it.
func (r *rxReorderBuffer) deliver(fn EncReader) {
	for k := range r.buf {
		fn(r.buf[k].src, r.buf[k].buf, RxMeta{OuterECN: r.buf[k].ecn})
		r.buf[k].buf = nil
	}
}
