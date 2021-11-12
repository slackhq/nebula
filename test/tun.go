package test

import (
	"errors"
	"io"
	"net"

	"github.com/slackhq/nebula/iputil"
)

type NoopTun struct{}

func (NoopTun) RouteFor(iputil.VpnIp) iputil.VpnIp {
	return 0
}

func (NoopTun) Activate() error {
	return nil
}

func (NoopTun) Cidr() *net.IPNet {
	return nil
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
