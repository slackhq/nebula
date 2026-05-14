// Package overlaytest provides fakes of overlay.Device for tests that do
// not want to touch a real tun device or route table.
package overlaytest

import (
	"errors"
	"net/netip"

	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/wire"
)

// NoopTun is an overlay.Device that silently discards every read and write.
// Useful in tests that need to construct a nebula Interface but do not
// exercise the datapath.
type NoopTun struct{}

func (NoopTun) Capabilities() tio.Capabilities {
	return tio.Capabilities{}
}

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

func (NoopTun) Read(p []wire.TunPacket, mem []byte) (int, error) {
	return 0, nil
}

func (NoopTun) Write([]byte) (int, error) {
	return 0, nil
}

func (NoopTun) SupportsMultiqueue() bool {
	return false
}

func (NoopTun) NewMultiQueueReader() error {
	return errors.New("unsupported")
}

func (NoopTun) Readers() []tio.Queue {
	return []tio.Queue{NoopTun{}}
}

func (NoopTun) Close() error {
	return nil
}
