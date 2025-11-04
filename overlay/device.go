package overlay

import (
	"io"
	"net/netip"

	"github.com/slackhq/nebula/routing"
)

// BatchReadWriter extends io.ReadWriteCloser with batch I/O operations
type BatchReadWriter interface {
	io.ReadWriteCloser

	// BatchRead reads multiple packets at once
	BatchRead(bufs [][]byte, sizes []int) (int, error)

	// WriteBatch writes multiple packets at once
	WriteBatch(bufs [][]byte, offset int) (int, error)

	// BatchSize returns the optimal batch size for this device
	BatchSize() int
}

type Device interface {
	BatchReadWriter
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RoutesFor(netip.Addr) routing.Gateways
	SupportsMultiqueue() bool
	NewMultiQueueReader() (BatchReadWriter, error)
}
