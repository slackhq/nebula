package overlay

import (
	"io"
	"log/slog"
	"net/netip"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
	"github.com/slackhq/nebula/wire"
)

func NewUserDeviceFromConfig(c *config.C, l *slog.Logger, vpnNetworks []netip.Prefix, routines int) (Device, error) {
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
}

func (d *UserDevice) Capabilities() tio.Capabilities {
	return tio.Capabilities{}
}

func (d *UserDevice) Read(p []wire.TunPacket, mem []byte) (int, error) {
	if len(p) == 0 || len(mem) == 0 {
		return 0, nil //todo should this be an err?
	}
	p[0].Meta = struct{}{}
	n, err := d.outboundReader.Read(mem)
	if err != nil {
		return 0, err
	}
	p[0].Bytes = mem[:n]
	return 1, nil
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

func (d *UserDevice) Close() error {
	d.inboundWriter.Close()
	d.outboundWriter.Close()
	return nil
}
