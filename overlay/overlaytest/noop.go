// Package overlaytest provides fakes of overlay.Device for tests that do
// not want to touch a real tun device or route table.
package overlaytest

import (
	"errors"
	"io"
	"net/netip"

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

func (NoopTun) Read([]byte) (int, error) {
	return 0, nil
}

func (NoopTun) Write([]byte) (int, error) {
	return 0, nil
}

func (NoopTun) SupportsMultiqueue() bool {
	return false
}

func (NoopTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, errors.New("unsupported")
}

func (NoopTun) Close() error {
	return nil
}
