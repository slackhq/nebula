package overlay

import (
	"io"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
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
func (d *UserDevice) Networks() []netip.Prefix          { return d.vpnNetworks }
func (d *UserDevice) Name() string                      { return "faketun0" }
func (d *UserDevice) RouteFor(ip netip.Addr) netip.Addr { return ip }
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
