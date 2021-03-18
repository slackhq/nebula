package udp

import (
	"github.com/sirupsen/logrus"
	c "github.com/slackhq/nebula/config"
)

type EncReader func(
	addr *Addr,
	out []byte,
	packet []byte,
	header *Header,
	fwPacket *FirewallPacket,
	lhh LightHouseHandlerFunc,
	nb []byte,
	q int,
	localCache ConntrackCache,
)

type Conn interface {
	Rebind() error
	LocalAddr() (*Addr, error)
	ListenOut(reader EncReader, lhf LightHouseHandlerFunc, cache *ConntrackCacheTicker, q int) error
	WriteTo(b []byte, addr *Addr) error
	//TODO: an interface is going to be a lot cleaner than this
	ReloadConfig(config *c.Config)
	EmitStats()

	SetRecvBuffer(n int) error
	SetSendBuffer(n int) error
	GetRecvBuffer() (int, error)
	GetSendBuffer() (int, error)
	logger() *logrus.Logger
}

func configSetBuffers(conn Conn, c *c.Config) {
	b := c.GetInt("listen.read_buffer", 0)
	if b > 0 {
		err := conn.SetRecvBuffer(b)
		if err != nil {
			conn.logger().WithError(err).Error("Failed to set listen.read_buffer")
		}
	}

	s, err := conn.GetRecvBuffer()
	if err == nil {
		conn.logger().WithField("size", s).Info("listen.read_buffer")
	} else {
		conn.logger().WithError(err).Warn("Failed to get listen.read_buffer")
	}

	b = c.GetInt("listen.write_buffer", 0)
	if b > 0 {
		err := conn.SetSendBuffer(b)
		if err != nil {
			conn.logger().WithError(err).Error("Failed to set listen.write_buffer")
		}
	}

	s, err = conn.GetSendBuffer()
	if err == nil {
		conn.logger().WithField("size", s).Info("listen.write_buffer")
	} else {
		conn.logger().WithError(err).Warn("Failed to get listen.write_buffer")
	}
}
