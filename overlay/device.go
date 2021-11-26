package overlay

import (
	"io"
	"net"

	"github.com/slackhq/nebula/iputil"
)

type Device interface {
	io.ReadWriteCloser
	Activate() error
	Cidr() *net.IPNet
	Name() string
	RouteFor(iputil.VpnIp) iputil.VpnIp
	NewMultiQueueReader() (io.ReadWriteCloser, error)
}
