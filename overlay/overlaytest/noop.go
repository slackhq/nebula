// Package overlaytest provides fakes of overlay.Device for tests that do
// not want to touch a real tun device or route table.
package overlaytest

import (
	"net/netip"

	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
)

// NoopTun is an overlay.Device that silently discards every read and write.
// Useful in tests that need to construct a nebula Interface but do not
// exercise the datapath.
type NoopTun struct{}

func (NoopTun) RoutesFor(addr netip.Addr) routing.Gateways {
	return routing.Gateways{}
}

func (NoopTun) Activate() error {
	return nil
}

func (NoopTun) Networks() []netip.Prefix {
	return []netip.Prefix{}
}

func (NoopTun) Name() string {
	return "noop"
}

func (NoopTun) Read() ([]tio.Packet, error) {
	return nil, nil
}

func (NoopTun) Write([]byte) (int, error) {
	return 0, nil
}

func (NoopTun) Queues(int) ([]tio.Queue, error) {
	return []tio.Queue{NoopTun{}}, nil
}

func (NoopTun) Close() error {
	return nil
}
