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
	// TunPrefixLen reports the number of bytes the device prepends to every IP packet on the wire.
	// Currently only non zero for the BSD tun devices.
	TunPrefixLen() int
}
