package overlay

import (
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
)

func NewUserDeviceFromConfig(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (Device, error) {
	return NewUserDevice(tunCidr)
}

func NewUserDevice(tunCidr *net.IPNet) (Device, error) {
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
	tunCidr *net.IPNet

	outboundReader *io.PipeReader
	outboundWriter *io.PipeWriter

	inboundReader *io.PipeReader
	inboundWriter *io.PipeWriter
}

func (d *UserDevice) Activate() error {
	return nil
}
func (d *UserDevice) Cidr() *net.IPNet                      { return d.tunCidr }
func (d *UserDevice) Name() string                          { return "faketun0" }
func (d *UserDevice) RouteFor(ip iputil.VpnIp) iputil.VpnIp { return ip }
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
