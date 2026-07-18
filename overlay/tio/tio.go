package tio

import (
	"io"
)

// QueueSet holds one or many Queue objects and helps close them in an orderly way.
type QueueSet interface {
	io.Closer
	Queues() []Queue

	// Add takes a tun fd, adds it to the set, and prepares it for use as a Queue.
	Add(fd int) error
}

// Capabilities advertises which kernel offload features a Queue
// successfully negotiated. Callers consult this to decide which coalescers
// to wire onto the write path — a Queue without TSO can't usefully accept a
// TCPCoalescer, and a Queue without USO can't accept a UDPCoalescer.
type Capabilities struct {
	// TSO means the FD was opened with IFF_VNET_HDR and the kernel agreed
	// to TUN_F_TSO4|TSO6 — i.e. WriteGSO with GSOProtoTCP is safe.
	TSO bool
	// USO means the kernel additionally agreed to TUN_F_USO4|USO6, so
	// WriteGSO with GSOProtoUDP is safe. Linux ≥ 6.2.
	USO bool
}

// Queue is a readable/writable Poll queue. Concurrency contract: a single
// read goroutine drives Read; plain Write is safe for concurrent callers;
// WriteGSO (on Queues that implement GSOWriter) is single-writer per queue.
type Queue interface {
	io.Closer

	// Read returns one or more packets. The returned Packet.Bytes slices
	// are borrowed from the Queue's internal buffer and are only valid
	// until the next Read or Close on this Queue - callers must encrypt
	// or copy each slice before the next call. A Packet may carry a
	// GSO/USO superpacket (see GSOInfo); when GSO.IsSuperpacket() is
	// true the caller must segment Bytes before treating it as a single
	// IP datagram. Single-reader only: not safe for concurrent Reads (it
	// reuses per-queue rx scratch each call).
	Read() ([]Packet, error)

	// Write emits a single packet on the plaintext (outside→inside)
	// delivery path. Safe for concurrent use.
	Write(p []byte) (int, error)
}

// Packet is the unit Queue.Read returns. Bytes points into the queue's
// internal buffer and is only valid until the next Read or Close on the
// queue that produced it. GSO is the zero value for an already-segmented
// IP datagram; when non-zero it describes a kernel-supplied TSO/USO
// superpacket the caller must segment before consuming.
type Packet struct {
	Bytes []byte
	GSO   GSOInfo
}

// GSOInfo describes a kernel-supplied superpacket sitting in Packet.Bytes.
// The zero value means "not a superpacket" — Bytes is one regular IP
// datagram and no segmentation is required.
type GSOInfo struct {
	// Size is the GSO segment size: max payload bytes per segment
	// (== TCP MSS for TSO, == UDP payload chunk for USO). Zero means
	// not a superpacket.
	Size uint16
	// HdrLen is the total L3+L4 header length within Bytes (already
	// corrected via correctHdrLen, so safe to slice on).
	HdrLen uint16
	// CsumStart is the L4 header offset inside Bytes (== L3 header
	// length).
	CsumStart uint16
	// Proto picks the L4 protocol (TCP or UDP) so the segmenter knows
	// which checksum/header layout to apply.
	Proto GSOProto
}

// IsSuperpacket reports whether g describes a multi-segment GSO/USO
// superpacket that needs segmentation before its bytes can be encrypted
// and sent on the wire.
func (g GSOInfo) IsSuperpacket() bool { return g.Size > 0 }

// Clone returns a Packet whose Bytes is a freshly allocated copy of p.Bytes,
// safe to retain past the next Read or Close on the originating Queue.
// GSO metadata is copied verbatim. Use this only when a caller genuinely
// needs to outlive the borrowed-slice contract — the hot path reads should
// continue to consume the borrow synchronously to avoid the allocation.
func (p Packet) Clone() Packet {
	if p.Bytes == nil {
		return p
	}
	cp := make([]byte, len(p.Bytes))
	copy(cp, p.Bytes)
	return Packet{Bytes: cp, GSO: p.GSO}
}

// CapsProvider is an optional interface implemented by Queues that
// successfully negotiated kernel offload features at open time. Callers
// pick a write-path coalescer based on the result. Queues that don't
// implement it are treated as having no offload capability — callers must
// fall back to plain per-packet writes.
type CapsProvider interface {
	Capabilities() Capabilities
}

// QueueCapabilities returns q's negotiated offload capabilities, or the
// zero value when q does not advertise any.
func QueueCapabilities(q Queue) Capabilities {
	if cp, ok := q.(CapsProvider); ok {
		return cp.Capabilities()
	}
	return Capabilities{}
}

// GSOProto selects the L4 protocol for a GSO superpacket. Determines which
// VIRTIO_NET_HDR_GSO_* type the writer stamps and which checksum offset
// inside the transport header virtio NEEDS_CSUM expects.
type GSOProto uint8

const (
	GSOProtoTCP GSOProto = iota
	GSOProtoUDP
)

// GSOWriter is implemented by Queues that can emit a TCP or UDP superpacket
// assembled from a header prefix plus one or more borrowed payload
// fragments, in a single vectored write (writev with a leading
// virtio_net_hdr). This lets the coalescer avoid copying payload bytes
// between the caller's decrypt buffer and the TUN. Backends without GSO
// support do not implement this interface and coalescing is skipped.
//
// hdr contains the IPv4/IPv6 header prefix (mutable - callers will have
// filled in total length and IP csum). transportHdr is the TCP or UDP
// header (mutable - the L4 checksum field must hold the pseudo-header
// partial, single-fold not inverted, per virtio NEEDS_CSUM semantics).
// pays are non-overlapping payload fragments whose concatenation is the
// full superpacket payload; they are read-only from the writer's
// perspective and must remain valid until the call returns. Every segment
// in pays except possibly the last is exactly the same size. proto picks
// the L4 protocol so the writer knows which GSOType / CsumOffset to set.
//
// Callers should also consult CapsProvider (via SupportsGSO or
// QueueCapabilities) for the per-protocol negotiated capability; an
// implementation of GSOWriter is necessary but not sufficient since USO
// may not have been negotiated even when TSO was.
type GSOWriter interface {
	WriteGSO(hdr []byte, transportHdr []byte, pays [][]byte, proto GSOProto) error
}

// SupportsGSO reports whether w implements GSOWriter and the underlying
// queue advertises the negotiated capability for `want`. A writer that
// implements GSOWriter but not CapsProvider is treated as permissive
// (used by tests and fakes that don't negotiate).
func SupportsGSO(w any, want GSOProto) (GSOWriter, bool) {
	gw, ok := w.(GSOWriter)
	if !ok {
		return nil, false
	}
	cp, ok := w.(CapsProvider)
	if !ok {
		return gw, true
	}
	caps := cp.Capabilities()
	switch want {
	case GSOProtoTCP:
		return gw, caps.TSO
	case GSOProtoUDP:
		return gw, caps.USO
	}
	return gw, false
}
