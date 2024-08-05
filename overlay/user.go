package overlay

import (
	"io"
	"net/netip"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

func NewUserDeviceFromConfig(c *config.C, l *logrus.Logger, tunCidr netip.Prefix, routines int) (Device, error) {
	d, err := NewUserDevice(tunCidr)
	if err != nil {
		return nil, err
	}

	_, routes, err := getAllRoutesFromConfig(c, tunCidr, true)
	if err != nil {
		return nil, err
	}

	routeTree, err := makeRouteTree(l, routes, true)
	if err != nil {
		return nil, err
	}

	newDefaultMTU := c.GetInt("tun.mtu", DefaultMTU)
	for i, r := range routes {
		if r.MTU == 0 {
			routes[i].MTU = newDefaultMTU
		}
	}

	d.routeTree.Store(routeTree)

	return d, nil
}

func NewUserDevice(tunCidr netip.Prefix) (*UserDevice, error) {
	// these pipes guarantee each write/read will match 1:1
	or, ow := io.Pipe()
	ir, iw := io.Pipe()
	return &UserDevice{
		tunCidr:        tunCidr,
		outboundReader: or,
		outboundWriter: ow,
		inboundReader:  ir,
		inboundWriter:  iw,
	}, nil
}

type UserDevice struct {
	tunCidr netip.Prefix

	outboundReader *io.PipeReader
	outboundWriter *io.PipeWriter

	inboundReader *io.PipeReader
	inboundWriter *io.PipeWriter

	routeTree atomic.Pointer[bart.Table[netip.Addr]]
}

func (d *UserDevice) Activate() error {
	return nil
}
func (d *UserDevice) Cidr() netip.Prefix                { return d.tunCidr }
func (d *UserDevice) Name() string                      { return "faketun0" }
func (d *UserDevice) RouteFor(ip netip.Addr) netip.Addr {
	ptr := d.routeTree.Load()
	if ptr != nil {
		r, _ := d.routeTree.Load().Lookup(ip)
		return r
	} else {
		return ip
	}
}
func (d *UserDevice) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return d, nil
}

func (d *UserDevice) Pipe() (*io.PipeReader, *io.PipeWriter) {
	return d.inboundReader, d.outboundWriter
}

func (d *UserDevice) Read(p []byte) (n int, err error) {
	return d.outboundReader.Read(p)
}
func (d *UserDevice) Write(p []byte) (n int, err error) {
	return d.inboundWriter.Write(p)
}
func (d *UserDevice) Close() error {
	d.inboundWriter.Close()
	d.outboundWriter.Close()
	return nil
}
