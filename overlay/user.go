package overlay

import (
	"io"
	"log/slog"
	"net/netip"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
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

func (d *UserDevice) Queues(n int) ([]tio.Queue, error) {
	out := make([]tio.Queue, n)
	for i := range out {
		// All queues share the underlying pipes (the io.Pipe serializes
		// concurrent callers) but each owns a private scratch buffer so
		// concurrent Reads across queues never alias. NoClose: the pipes are
		// owned by the UserDevice and torn down once by UserDevice.Close.
		out[i] = tio.NewSingleQueueNoClose(d, defaultBatchBufSize)
	}
	return out, nil
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
