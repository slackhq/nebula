package overlay

import (
	"io"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
)

func NewUserDeviceFromConfig(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, routines int) (Device, error) {
	return NewUserDevice(vpnNetworks)
}

func NewUserDevice(vpnNetworks []netip.Prefix) (Device, error) {
	// these pipes guarantee each write/read will match 1:1
	or, ow := io.Pipe()
	ir, iw := io.Pipe()
	return &UserDevice{
		vpnNetworks:    vpnNetworks,
		outboundReader: or,
		outboundWriter: ow,
		inboundReader:  ir,
		inboundWriter:  iw,
	}, nil
}

type UserDevice struct {
	vpnNetworks []netip.Prefix

	outboundReader *io.PipeReader
	outboundWriter *io.PipeWriter

	inboundReader *io.PipeReader
	inboundWriter *io.PipeWriter
}

func (d *UserDevice) Activate() error {
	return nil
}

func (d *UserDevice) Networks() []netip.Prefix { return d.vpnNetworks }
func (d *UserDevice) Name() string             { return "faketun0" }
func (d *UserDevice) RoutesFor(ip netip.Addr) routing.Gateways {
	return routing.Gateways{routing.NewGateway(ip, 1)}
}

func (d *UserDevice) NewMultiQueueReader() (BatchReadWriter, error) {
	return d, nil
}

// BatchRead reads a single packet (batch size 1 for UserDevice)
func (d *UserDevice) BatchRead(bufs [][]byte, sizes []int) (int, error) {
	n, err := d.Read(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// WriteBatch writes packets individually (no batching for UserDevice)
func (d *UserDevice) WriteBatch(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		_, err := d.Write(buf[offset:])
		if err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

// BatchSize returns 1 for UserDevice (no batching)
func (d *UserDevice) BatchSize() int {
	return 1
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
