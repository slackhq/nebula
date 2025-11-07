package overlay

import (
	"net/netip"

	"github.com/slackhq/nebula/routing"
)

type Device interface {
	TunDev
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RoutesFor(netip.Addr) routing.Gateways
	SupportsMultiqueue() bool
	NewMultiQueueReader() (TunDev, error)
}
