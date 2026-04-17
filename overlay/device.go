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
