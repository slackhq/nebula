package overlay

import (
	"fmt"
	"io"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/packet"
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

func (d *UserDevice) NewPacketArrays(batchSize int) []TunPacket {
	//inPackets := make([]TunPacket, batchSize)
	//outPackets := make([]OutPacket, batchSize)
	panic("not implemented") //todo!
	//for i := 0; i < batchSize; i++ {
	//	inPackets[i] = vhostnet.NewVIO()
	//	outPackets[i] = packet.New(false)
	//}
	//return inPackets, outPackets
}

func (d *UserDevice) RecycleRxSeg(pkt TunPacket, kick bool, q int) error {
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

func (d *UserDevice) NewMultiQueueReader() (TunDev, error) {
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

func (d *UserDevice) ReadMany(b []TunPacket, _ int) (int, error) {
	_, err := d.Read(b[0].GetPayload())
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (d *UserDevice) AllocSeg(pkt *packet.OutPacket, q int) (int, error) {
	return 0, fmt.Errorf("user: AllocSeg not implemented")
}

func (d *UserDevice) WriteOne(x *packet.OutPacket, kick bool, q int) (int, error) {
	return 0, fmt.Errorf("user: WriteOne not implemented")
}

func (d *UserDevice) WriteMany(x []*packet.OutPacket, q int) (int, error) {
	return 0, fmt.Errorf("user: WriteMany not implemented")
}
