package overlay

import (
	"errors"
	"net/netip"

	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
)

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

func (NoopTun) Read() ([][]byte, error) {
	return nil, nil
}

func (NoopTun) Write([]byte) (int, error) {
	return 0, nil
}

func (NoopTun) WriteFromSelf(p []byte) (int, error) {
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
