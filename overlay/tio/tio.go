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
	//none yet!
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
