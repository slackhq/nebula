package tio

import (
	"io"

	"github.com/slackhq/nebula/wire"
)

// QueueSet holds one or many Queue objects and helps close them in an orderly way.
type QueueSet interface {
	io.Closer
	Queues() []Queue

	// Add takes a tun fd, adds it to the set, and prepares it for use as a Queue.
	Add(fd int) error
}

// Capabilities advertises which kernel offload features a Queue successfully negotiated.
// Callers consult this to decide which coalescers to wire onto the write path.
type Capabilities struct {
	// TSO means the FD was opened with IFF_VNET_HDR and the kernel agreed
	// to TUN_F_TSO4|TSO6 — i.e. WriteGSO with GSOProtoTCP is safe.
	TSO bool
	// USO means the kernel additionally agreed to TUN_F_USO4|USO6, so
	// WriteGSO with GSOProtoUDP is safe. Linux ≥ 6.2.
	USO bool
}

// Queue is a readable/writable Poll queue. One Queue is driven by a single
// read goroutine plus a single writer (see Write below).
type Queue interface {
	io.Closer

	// Read will read at least 1 packet from the tun (up to len(p)).
	// mem will be used to provide the backing for each of p[n].Bytes.
	// Callers should size mem and p to avoid exhausting mem before p.
	// Returns the number of packets actually read, or error.
	Read(p []wire.TunPacket, mem []byte) (int, error)

	// Write emits a single packet on the plaintext (outside→inside)
	// delivery path.
	Write(p []byte) (int, error)

	// Capabilities returns the Queue's negotiated offload capabilities,
	// or the zero value when q does not advertise any.
	Capabilities() Capabilities
}

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
	WriteGSO(hdr []byte, transportHdr []byte, pays [][]byte, proto wire.GSOProto) error
}

// SupportsGSO reports whether w implements GSOWriter and the underlying
// queue advertises the negotiated capability for `want`. A writer that
// implements GSOWriter but not CapsProvider is treated as permissive
// (used by tests and fakes that don't negotiate).
func SupportsGSO(w Queue, want wire.GSOProto) (GSOWriter, bool) {
	gw, ok := w.(GSOWriter)
	if !ok {
		return nil, false
	}
	caps := w.Capabilities()
	switch want {
	case wire.GSOProtoTCP:
		return gw, caps.TSO
	case wire.GSOProtoUDP:
		return gw, caps.USO
	default:
		return gw, false
	}
}
