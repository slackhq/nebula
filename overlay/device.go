package overlay

import (
	"io"
	"net/netip"
)

type Device interface {
	io.ReadWriteCloser
	Activate() error
	Networks() []netip.Prefix
	Name() string
	RouteFor(netip.Addr) netip.Addr
	NewMultiQueueReader() (io.ReadWriteCloser, error)
}
