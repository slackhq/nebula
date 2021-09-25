package nebula

import (
	"fmt"
	"io"
	"net"
)

//A fake Tun interface, for when a Tun isn't possible or desireable for this node (e.g. lacking Admin priviledges, embedding into programs, etc.)
type FakeTun struct {
	sendingPackets  chan []byte //Data from this node, to be sent into the nebula network
	receivedPackets chan []byte //Data for this node, received from the nebula network
	cidr            *net.IPNet  //see Inside.CidrNet(). More-or-less nebula IP address/range of the node
	deviceName      string
}

//Caller can provide unbuffered or buffered channels, thus deciding if FakeTun runs synchronous or asynchronous (respectively)
func NewFakeTun(deviceName string, cidr *net.IPNet, sendingPackets chan []byte, receivedPackets chan []byte) *FakeTun {
	return &FakeTun{
		cidr:            cidr,
		sendingPackets:  sendingPackets,
		receivedPackets: receivedPackets,
		deviceName:      deviceName,
	}
}

func (c *FakeTun) Activate() (err error) {
	return
}

func (c *FakeTun) CidrNet() *net.IPNet {
	return c.cidr
}

func (c *FakeTun) DeviceName() string {
	return c.deviceName
}

func (c *FakeTun) Write(b []byte) (n int, err error) {
	return len(b), c.WriteRaw(b)
}

func (c *FakeTun) Close() error {
	return nil
}

func (c *FakeTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("NewMultiQueueReader not supported by FakeTun\n")
}

func (c *FakeTun) WriteRaw(b []byte) error {
	buff := make([]byte, len(b))
	copy(buff, b)
	c.receivedPackets <- buff //Data received by this node
	return nil
}

func (c *FakeTun) Read(b []byte) (int, error) {
	buff := <-c.sendingPackets //Data to be sent by this node
	n := copy(b, buff)
	return n, nil
}
