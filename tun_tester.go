// +build e2e_testing

package nebula

import (
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

type Tun struct {
	Device       string
	Cidr         *net.IPNet
	MTU          int
	UnsafeRoutes []route
	l            *logrus.Logger

	rxPackets chan []byte // Packets to receive into nebula
	txPackets chan []byte // Packets transmitted outside by nebula
}

func newTun(l *logrus.Logger, deviceName string, cidr *net.IPNet, defaultMTU int, _ []route, unsafeRoutes []route, _ int, _ bool) (ifce *Tun, err error) {
	return &Tun{
		Device:       deviceName,
		Cidr:         cidr,
		MTU:          defaultMTU,
		UnsafeRoutes: unsafeRoutes,
		l:            l,
		rxPackets:    make(chan []byte, 1),
		txPackets:    make(chan []byte, 1),
	}, nil
}

func newTunFromFd(_ *logrus.Logger, _ int, _ *net.IPNet, _ int, _ []route, _ []route, _ int) (ifce *Tun, err error) {
	return nil, fmt.Errorf("newTunFromFd not supported")
}

// Send will place a byte array onto the receive queue for nebula to consume
// These are unencrypted ip layer frames destined for another nebula node.
// packets should exit the udp side, capture them with udpConn.Get
func (c *Tun) Send(packet []byte) {
	c.l.WithField("dataLen", len(packet)).Info("Tun receiving injected packet")
	c.rxPackets <- packet
}

// Get will pull an unencrypted ip layer frame from the transmit queue
// nebula meant to send this message to some application on the local system
// packets were ingested from the udp side, you can send them with udpConn.Send
func (c *Tun) Get(block bool) []byte {
	if block {
		return <-c.txPackets
	}

	select {
	case p := <-c.txPackets:
		return p
	default:
		return nil
	}
}

//********************************************************************************************************************//
// Below this is boilerplate implementation to make nebula actually work
//********************************************************************************************************************//

func (c *Tun) Activate() error {
	return nil
}

func (c *Tun) CidrNet() *net.IPNet {
	return c.Cidr
}

func (c *Tun) DeviceName() string {
	return c.Device
}

func (c *Tun) Write(b []byte) (n int, err error) {
	return len(b), c.WriteRaw(b)
}

func (c *Tun) Close() error {
	close(c.rxPackets)
	return nil
}

func (c *Tun) WriteRaw(b []byte) error {
	packet := make([]byte, len(b), len(b))
	copy(packet, b)
	c.txPackets <- packet
	return nil
}

func (c *Tun) Read(b []byte) (int, error) {
	p := <-c.rxPackets
	copy(b, p)
	return len(p), nil
}

func (c *Tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented")
}
