//go:build e2e_testing
// +build e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/packet"
	"github.com/slackhq/nebula/routing"
)

type TestTun struct {
	Device      string
	vpnNetworks []netip.Prefix
	Routes      []Route
	routeTree   *bart.Table[routing.Gateways]
	l           *logrus.Logger

	closed    atomic.Bool
	rxPackets chan []byte // Packets to receive into nebula
	TxPackets chan []byte // Packets transmitted outside by nebula
	buffers   [][]byte
}

func newTun(c *config.C, l *logrus.Logger, vpnNetworks []netip.Prefix, _ bool) (*TestTun, error) {
	_, routes, err := getAllRoutesFromConfig(c, vpnNetworks, true)
	if err != nil {
		return nil, err
	}
	routeTree, err := makeRouteTree(l, routes, false)
	if err != nil {
		return nil, err
	}

	return &TestTun{
		Device:      c.GetString("tun.dev", ""),
		vpnNetworks: vpnNetworks,
		Routes:      routes,
		routeTree:   routeTree,
		l:           l,
		rxPackets:   make(chan []byte, 10),
		TxPackets:   make(chan []byte, 10),
	}, nil
}

func newTunFromFd(_ *config.C, _ *logrus.Logger, _ int, _ []netip.Prefix) (*TestTun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported")
}

// Send will place a byte array onto the receive queue for nebula to consume
// These are unencrypted ip layer frames destined for another nebula node.
// packets should exit the udp side, capture them with udpConn.Get
func (t *TestTun) Send(packet []byte) {
	if t.closed.Load() {
		return
	}

	if t.l.Level >= logrus.DebugLevel {
		t.l.WithField("dataLen", len(packet)).Debug("Tun receiving injected packet")
	}
	t.rxPackets <- packet
}

// Get will pull an unencrypted ip layer frame from the transmit queue
// nebula meant to send this message to some application on the local system
// packets were ingested from the udp side, you can send them with udpConn.Send
func (t *TestTun) Get(block bool) []byte {
	if block {
		return <-t.TxPackets
	}

	select {
	case p := <-t.TxPackets:
		return p
	default:
		return nil
	}
}

//********************************************************************************************************************//
// Below this is boilerplate implementation to make nebula actually work
//********************************************************************************************************************//

func (t *TestTun) RoutesFor(ip netip.Addr) routing.Gateways {
	r, _ := t.routeTree.Lookup(ip)
	return r
}

func (t *TestTun) Activate() error {
	return nil
}

func (t *TestTun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (t *TestTun) Name() string {
	return t.Device
}

func (t *TestTun) ReadMany(x []*packet.VirtIOPacket, q int) (int, error) {
	p, ok := <-t.rxPackets
	if !ok {
		return 0, os.ErrClosed
	}
	x[0].Payload = p
	return 1, nil
}

func (t *TestTun) AllocSeg(pkt *packet.OutPacket, q int) (int, error) {
	buf := make([]byte, 9000)
	t.buffers = append(t.buffers, buf)
	idx := len(t.buffers) - 1
	isV6 := false //todo?
	x := pkt.UseSegment(uint16(idx), buf, isV6)
	return x, nil
}

func (t *TestTun) Write(b []byte) (int, error) {
	//todo garbagey
	out := packet.NewOut()
	x, err := t.AllocSeg(out, 0)
	if err != nil {
		return 0, err
	}
	copy(out.SegmentPayloads[x], b)
	return t.WriteOne(out, true, 0)
}

func (t *TestTun) WriteOne(x *packet.OutPacket, kick bool, q int) (int, error) {
	if t.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(x.SegmentIDs) == 0 {
		return 0, nil
	}
	for i, _ := range x.SegmentIDs {
		t.TxPackets <- x.SegmentPayloads[i]
	}
	//todo if kick, delete alloced seg

	return 1, nil
}

func (t *TestTun) WriteMany(x []*packet.OutPacket, q int) (int, error) {
	if len(x) == 0 {
		return 0, nil
	}

	for _, pkt := range x {
		_, err := t.WriteOne(pkt, true, q)
		if err != nil {
			return 0, err
		}
	}

	return len(x), nil
}

func (t *TestTun) RecycleRxSeg(pkt *packet.VirtIOPacket, kick bool, q int) error {
	//todo this ought to maybe track something
	return nil
}

func (t *TestTun) Close() error {
	if t.closed.CompareAndSwap(false, true) {
		close(t.rxPackets)
		close(t.TxPackets)
	}
	return nil
}

func (t *TestTun) SupportsMultiqueue() bool {
	return false
}

func (t *TestTun) NewMultiQueueReader() (TunDev, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented")
}
