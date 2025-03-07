package test

import (
	"errors"
	"io"
	"net/netip"
)

type NoopTun struct{}

func (NoopTun) RouteFor(addr netip.Addr) netip.Addr {
	return netip.Addr{}
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

func (NoopTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, errors.New("unsupported")
}

func (NoopTun) Close() error {
	return nil
}
