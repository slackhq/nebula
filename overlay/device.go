package overlay

import (
	"io"
	"net/netip"

	"github.com/slackhq/nebula/routing"
)

// defaultBatchBufSize is the per-Queue scratch size for ReadBatch on backends
// that don't do TSO segmentation. 65535 covers any single IP packet.
const defaultBatchBufSize = 65535

// Queue is a readable/writable tun queue. ReadBatch returns one or more
// packets; the returned slices are borrowed from the queue's internal buffer
// and are only valid until the next ReadBatch / Read / Close on this Queue.
// Callers must encrypt or copy each slice before the next call. Not safe for
// concurrent use — one goroutine per Queue.
type Queue interface {
	io.ReadWriteCloser
	ReadBatch() ([][]byte, error)
}

type Device interface {
	Queue
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RoutesFor(netip.Addr) routing.Gateways
	SupportsMultiqueue() bool
	NewMultiQueueReader() (Queue, error)
}

// GSOWriter is implemented by Queues that can emit a TCP TSO superpacket
// assembled from a header prefix plus one or more borrowed payload
// fragments, in a single vectored write (writev with a leading
// virtio_net_hdr). This lets the coalescer avoid copying payload bytes
// between the caller's decrypt buffer and the TUN. Backends without GSO
// support return false from GSOSupported and coalescing is skipped.
//
// hdr contains the IPv4/IPv6 + TCP header prefix (mutable — callers will
// have filled in total length and pseudo-header partial). pays are
// non-overlapping payload fragments whose concatenation is the full
// superpacket payload; they are read-only from the writer's perspective
// and must remain valid until the call returns. gsoSize is the MSS:
// every segment except possibly the last is exactly that many bytes.
// csumStart is the byte offset where the TCP header begins within hdr.
//
// hdr's TCP checksum field must already hold the pseudo-header partial
// sum (single-fold, not inverted), per virtio NEEDS_CSUM semantics.
type GSOWriter interface {
	WriteGSO(hdr []byte, pays [][]byte, gsoSize uint16, isV6 bool, csumStart uint16) error
	GSOSupported() bool
}
