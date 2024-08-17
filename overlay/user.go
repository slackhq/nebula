package overlay

import (
	"io"
	"net/netip"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"gvisor.dev/gvisor/pkg/buffer"
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
	return &UserDevice{
		tunCidr:         tunCidr,
		outboundChannel: make(chan *buffer.View, 16),
		inboundChannel:  make(chan *buffer.View, 16),
	}, nil
}

type UserDevice struct {
	tunCidr netip.Prefix

	outboundChannel chan *buffer.View
	inboundChannel  chan *buffer.View

	routeTree atomic.Pointer[bart.Table[netip.Addr]]
}

func (d *UserDevice) Activate() error {
	return nil
}
func (d *UserDevice) Cidr() netip.Prefix { return d.tunCidr }
func (d *UserDevice) Name() string       { return "faketun0" }
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

func (d *UserDevice) Pipe() (<-chan *buffer.View, chan<- *buffer.View) {
	return d.inboundChannel, d.outboundChannel
}

func (d *UserDevice) Read(p []byte) (n int, err error) {
	view, ok := <-d.outboundChannel
	if !ok {
		return 0, io.EOF
	}
	return view.Read(p)
}
func (d *UserDevice) WriteTo(w io.Writer) (n int64, err error) {
	view, ok := <-d.outboundChannel
	if !ok {
		return 0, io.EOF
	}
	return view.WriteTo(w)
}

func (d *UserDevice) Write(p []byte) (n int, err error) {
	view := buffer.NewViewWithData(p)
	d.inboundChannel <- view
	return view.Size(), nil
}
func (d *UserDevice) ReadFrom(r io.Reader) (n int64, err error) {
	view := buffer.NewViewSize(2048)
	n, err = view.ReadFrom(r)
	if n > 0 {
		d.inboundChannel <- view
	}
	return
}

func (d *UserDevice) Close() error {
	// There is nothing to be done for the UserDevice.
	// It doesn't start any goroutines on its own.
	// It doesn't manage any resources that needs closing.
	return nil
}
