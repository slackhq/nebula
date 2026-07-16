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

// Queue is a readable/writable packet queue. Concurrency contract: a single
// read goroutine drives Read; plain Write is safe for concurrent callers.
type Queue interface {
	io.Closer

	// Read returns one or more packets. The returned Packet.Bytes slices
	// are borrowed from the Queue's internal buffer and are only valid
	// until the next Read or Close on this Queue - callers must encrypt
	// or copy each slice before the next call. Single-reader only: not
	// safe for concurrent Reads (it reuses per-queue rx scratch each call).
	Read() ([]Packet, error)

	// Write emits a single packet on the plaintext (outside→inside)
	// delivery path. Safe for concurrent use.
	Write(p []byte) (int, error)
}

// Packet is the unit Queue.Read returns. Bytes points into the queue's
// internal buffer and is only valid until the next Read or Close on the
// queue that produced it.
type Packet struct {
	Bytes []byte
}

// Clone returns a Packet whose Bytes is a freshly allocated copy of p.Bytes,
// safe to retain past the next Read or Close on the originating Queue.
// Use this only when a caller genuinely needs to outlive the borrowed-slice
// contract — the hot path reads should continue to consume the borrow
// synchronously to avoid the allocation.
func (p Packet) Clone() Packet {
	if p.Bytes == nil {
		return p
	}
	cp := make([]byte, len(p.Bytes))
	copy(cp, p.Bytes)
	return Packet{Bytes: cp}
}
