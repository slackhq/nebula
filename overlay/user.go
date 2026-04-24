package overlay

import (
	"io"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/tio"
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
		numReaders:     1,
	}, nil
}

type UserDevice struct {
	vpnNetworks []netip.Prefix
	numReaders  int

	outboundReader *io.PipeReader
	outboundWriter *io.PipeWriter

	inboundReader *io.PipeReader
	inboundWriter *io.PipeWriter

	readBuf  []byte
	batchRet [1][]byte
}

func (d *UserDevice) Read() ([][]byte, error) {
	if d.readBuf == nil {
		d.readBuf = make([]byte, defaultBatchBufSize)
	}
	n, err := d.outboundReader.Read(d.readBuf)
	if err != nil {
		return nil, err
	}
	d.batchRet[0] = d.readBuf[:n]
	return d.batchRet[:], nil
}

func (d *UserDevice) Activate() error {
	return nil
}

func (d *UserDevice) Networks() []netip.Prefix { return d.vpnNetworks }
func (d *UserDevice) Name() string             { return "faketun0" }
func (d *UserDevice) RoutesFor(ip netip.Addr) routing.Gateways {
	return routing.Gateways{routing.NewGateway(ip, 1)}
}

func (d *UserDevice) SupportsMultiqueue() bool {
	return true
}

func (d *UserDevice) NewMultiQueueReader() error {
	d.numReaders++
	return nil
}

func (d *UserDevice) Readers() []tio.Queue {
	out := make([]tio.Queue, d.numReaders)
	for i := range d.numReaders {
		out[i] = d
	}
	return out
}

func (d *UserDevice) Pipe() (*io.PipeReader, *io.PipeWriter) {
	return d.inboundReader, d.outboundWriter
}

func (d *UserDevice) Write(p []byte) (n int, err error) {
	return d.inboundWriter.Write(p)
}
func (d *UserDevice) WriteFromSelf(p []byte) (n int, err error) {
	return d.Write(p)
}
func (d *UserDevice) Close() error {
	d.inboundWriter.Close()
	d.outboundWriter.Close()
	return nil
}
