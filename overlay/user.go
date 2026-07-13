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

// userDeviceQueue is a single tio.Queue over a UserDevice's shared pipes.
// One is handed to each tun read goroutine by Readers(). All queues delegate
// reads to the same outboundReader and writes to the same inboundWriter (the
// io.Pipe serializes concurrent callers), but every queue owns a private
// readBuf/batchRet so the borrowed Packet.Bytes slice one goroutine returns is
// never clobbered by another goroutine's concurrent Read.
type userDeviceQueue struct {
	outboundReader *io.PipeReader
	inboundWriter  *io.PipeWriter

	readBuf  []byte
	batchRet [1]tio.Packet
}

func (q *userDeviceQueue) Read() ([]tio.Packet, error) {
	n, err := q.outboundReader.Read(q.readBuf)
	if err != nil {
		return nil, err
	}
	q.batchRet[0] = tio.Packet{Bytes: q.readBuf[:n]}
	return q.batchRet[:], nil
}

func (q *userDeviceQueue) Write(p []byte) (int, error) {
	return q.inboundWriter.Write(p)
}

// Close is a no-op: the shared pipes are owned by the UserDevice and torn
// down by UserDevice.Close, so an individual queue must not close them out
// from under its siblings.
func (q *userDeviceQueue) Close() error {
	return nil
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
		// Each queue shares the underlying pipes but owns its own scratch
		// buffer so concurrent Reads across queues never alias.
		out[i] = &userDeviceQueue{
			outboundReader: d.outboundReader,
			inboundWriter:  d.inboundWriter,
			readBuf:        make([]byte, defaultBatchBufSize),
		}
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
