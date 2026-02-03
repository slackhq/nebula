package overlay

import (
	"io"
	"net/netip"

	"github.com/slackhq/nebula/routing"
)

type Device interface {
	io.ReadWriteCloser
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RoutesFor(netip.Addr) routing.Gateways
	SupportsMultiqueue() bool
	NewMultiQueueReader() (io.ReadWriteCloser, error)
}

// BatchReader is an optional interface that devices can implement
// to support reading multiple packets in a single batch operation.
// This can significantly reduce syscall overhead under high load.
type BatchReader interface {
	// ReadBatch reads up to len(packets) packets into the provided buffers.
	// Each packet is read into packets[i] and its length is stored in sizes[i].
	// Returns the number of packets read, or an error.
	// A return of (0, nil) indicates no packets were available (non-blocking).
	ReadBatch(packets [][]byte, sizes []int) (int, error)
}

// AsBatchReader returns a BatchReader if the reader supports batch operations,
// otherwise returns nil.
func AsBatchReader(r io.ReadWriteCloser) BatchReader {
	if br, ok := r.(BatchReader); ok {
		return br
	}
	return nil
}

// BatchEnabler is an optional interface for devices that need explicit
// enabling of batch read support (e.g., setting non-blocking mode).
type BatchEnabler interface {
	EnableBatchReading() error
}

// EnableBatchReading enables batch reading on the device if supported.
// Returns nil if the device doesn't support or need explicit enabling.
func EnableBatchReading(d interface{}) error {
	if be, ok := d.(BatchEnabler); ok {
		return be.EnableBatchReading()
	}
	return nil
}
