package overlay

import (
	"io"
	"net/netip"

	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
)

// defaultBatchBufSize is the per-Queue scratch size for Read on backends
// that don't do TSO segmentation. 65535 covers any single IP packet.
const defaultBatchBufSize = 65535

type Device interface {
	io.Closer
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RoutesFor(netip.Addr) routing.Gateways
	SupportsMultiqueue() bool //todo remove?
	NewMultiQueueReader() error
	Readers() []tio.Queue
}
