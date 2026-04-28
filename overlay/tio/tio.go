package tio

import (
	"io"
)

// defaultBatchBufSize is the per-Queue scratch size for Read on backends
// that don't do TSO segmentation. 65535 covers any single IP packet.
const defaultBatchBufSize = 65535

// Container holds one or many Queue objects and helps close them in an orderly way
type Container interface {
	io.Closer
	Queues() []Queue

	// Add takes a tun fd, adds it to the container, and prepares it for use as a Queue
	Add(fd int) error

	io.Closer
}

// Queue is a readable/writable Poll queue. One Queue is driven by a single
// read goroutine plus concurrent writers (see Write / WriteReject below).
type Queue interface {
	io.Closer

	// Read returns one or more packets. The returned slices are borrowed
	// from the Queue's internal buffer and are only valid until the next
	// Read or Close on this Queue - callers must encrypt or copy each
	// slice before the next call. Not safe for concurrent Reads.
	Read() ([][]byte, error)

	// Write emits a single packet on the plaintext (outside→inside)
	// delivery path. Not safe for concurrent Writes.
	Write(p []byte) (int, error)
}

// GSOWriter is implemented by Queues that can emit a TCP TSO superpacket
// assembled from a header prefix plus one or more borrowed payload
// fragments, in a single vectored write (writev with a leading
// virtio_net_hdr). This lets the coalescer avoid copying payload bytes
// between the caller's decrypt buffer and the TUN. Backends without GSO
// support return false from GSOSupported and coalescing is skipped.
//
// hdr contains the IPv4/IPv6 + TCP header prefix (mutable - callers will
// have filled in total length and pseudo-header partial). pays are
// non-overlapping payload fragments whose concatenation is the full
// superpacket payload; they are read-only from the writer's perspective
// and must remain valid until the call returns. gsoSize is the MSS:
// every segment except possibly the last is exactly that many bytes.
// csumStart is the byte offset where the TCP header begins within hdr.
//
// # TODO fold into Queue
//
// hdr's TCP checksum field must already hold the pseudo-header partial
// sum (single-fold, not inverted), per virtio NEEDS_CSUM semantics.
type GSOWriter interface {
	WriteGSO(hdr []byte, pays [][]byte, gsoSize uint16, csumStart uint16) error
	GSOSupported() bool
}
