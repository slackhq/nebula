package overlay

import (
	"io"
	"net/netip"

	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
)

type Device interface {
	io.Closer
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RoutesFor(netip.Addr) routing.Gateways
	SupportsMultiqueue() bool
	NewMultiQueueReader() error
	Readers() []tio.Queue
}
