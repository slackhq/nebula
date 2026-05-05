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
	// SupportsPerPeerMTU reports whether SetPeerMTU is implemented for real on
	// this platform. PMTUD requires this; the manager will refuse to enable when
	// false even if the operator set tun.max_mtu, because a discovered MTU we
	// can't actually install does the operator no good.
	SupportsPerPeerMTU() bool
	// SetPeerMTU installs a per-peer MTU on the routing table so the kernel will
	// surface PTB / EMSGSIZE for inside packets to that peer that would exceed mtu.
	// Pass mtu=0 to remove the override and let the device default apply.
	SetPeerMTU(addr netip.Addr, mtu int) error
}
