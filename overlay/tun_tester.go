//go:build e2e_testing
// +build e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
)

type TestTun struct {
	Device    string
	cidr      *net.IPNet
	Routes    []Route
	routeTree *cidr.Tree4
	l         *logrus.Logger

	closed    atomic.Bool
	rxPackets chan []byte // Packets to receive into nebula
	TxPackets chan []byte // Packets transmitted outside by nebula
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, _ int, routes []Route, _ int, _ bool, _ bool) (*TestTun, error) {
	routeTree, err := makeRouteTree(l, routes, false)
	if err != nil {
		return nil, err
	}

	return &TestTun{
		Device:    deviceName,
		cidr:      cidr,
		Routes:    routes,
		routeTree: routeTree,
		l:         l,
		rxPackets: make(chan []byte, 10),
		TxPackets: make(chan []byte, 10),
	}, nil
}

func newTunFromFd(_ *logrus.Logger, _ int, _ *net.IPNet, _ int, _ []Route, _ int, _ bool) (*TestTun, error) {
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

func (t *TestTun) RoutesFor(ip iputil.VpnIp) []iputil.VpnIp {
	r := t.routeTree.MostSpecificContains(ip)
	if r != nil {
		return []iputil.VpnIp{r.(iputil.VpnIp)}
	}

	return nil
}

func (t *TestTun) Activate() error {
	return nil
}

func (t *TestTun) Cidr() *net.IPNet {
	return t.cidr
}

func (t *TestTun) Name() string {
	return t.Device
}

func (t *TestTun) Write(b []byte) (n int, err error) {
	if t.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	packet := make([]byte, len(b), len(b))
	copy(packet, b)
	t.TxPackets <- packet
	return len(b), nil
}

func (t *TestTun) Close() error {
	if t.closed.CompareAndSwap(false, true) {
		close(t.rxPackets)
		close(t.TxPackets)
	}
	return nil
}

func (t *TestTun) Read(b []byte) (int, error) {
	p, ok := <-t.rxPackets
	if !ok {
		return 0, os.ErrClosed
	}
	copy(b, p)
	return len(p), nil
}

func (t *TestTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented")
}
