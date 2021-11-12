package overlay

import (
	"io"
	"net"

	"github.com/slackhq/nebula/iputil"
)

type Device interface {
	io.ReadWriteCloser
	Activate() error
	CidrNet() *net.IPNet
	DeviceName() string
	WriteRaw([]byte) error
	RouteFor(iputil.VpnIp) iputil.VpnIp
	NewMultiQueueReader() (io.ReadWriteCloser, error)
}
