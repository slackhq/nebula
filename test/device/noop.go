package device

import (
	"errors"
	"io"
	"net/netip"

	"github.com/slackhq/nebula/overlay"
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

func (NoopTun) Read([]byte) (int, error) {
	return 0, nil
}

func (NoopTun) Write([]byte) (int, error) {
	return 0, nil
}

func (NoopTun) SupportsMultiqueue() bool {
	return false
}

func (NoopTun) NewMultiQueueReader() (overlay.BatchReadWriter, error) {
	return nil, errors.New("unsupported")
}

func (NoopTun) Close() error {
	return nil
}

// BatchRead implements BatchReadWriter interface
func (NoopTun) BatchRead(bufs [][]byte, sizes []int) (int, error) {
	return 0, io.EOF
}

// WriteBatch implements BatchReadWriter interface
func (NoopTun) WriteBatch(bufs [][]byte, offset int) (int, error) {
	return len(bufs), nil
}

// BatchSize implements BatchReadWriter interface
func (NoopTun) BatchSize() int {
	return 1
}
