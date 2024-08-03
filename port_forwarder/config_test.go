package port_forwarder

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
)

func TestEmptyConfig(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString("bla:")
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 0)
	assert.True(t, fwd_list.IsEmpty())
}

func TestConfigWithNoProtocols(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:4499
    protocols: []
  inbound:
  - listen_port: 5599
    dial_address: 127.0.0.1:5599
    protocols: []
`)
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 0)
	assert.True(t, fwd_list.IsEmpty())
}

func TestConfigWithNoProtocols_commentedProtos(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:4499
    # protocols: [tcp, udp]
  inbound:
  - listen_port: 5599
    dial_address: 127.0.0.1:5599
    # protocols: [tc, udp]
`)
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 0)
	assert.True(t, fwd_list.IsEmpty())
}

func TestConfigWithNoProtocols_missing_in_out(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
`)
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 0)
	assert.True(t, fwd_list.IsEmpty())
}

func TestConfigWithTcpIn(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:4499
    protocols: []
  inbound:
  - listen_port: 5580
    dial_address: 127.0.0.1:5599
    protocols: [tcp]
`)
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 1)
	assert.False(t, fwd_list.IsEmpty())

	fwd1 := fwd_list.configPortForwardings["inbound.tcp.5580.127.0.0.1:5599"].(ForwardConfigIncomingTcp)
	assert.NotNil(t, fwd1)
	assert.Equal(t, fwd1.forwardLocalAddress, "127.0.0.1:5599")
	assert.Equal(t, int(fwd1.port), 5580)
}

func TestConfigWithTcpOut(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:4499
    protocols: [tcp]
  inbound:
  - listen_port: 5580
    dial_address: 127.0.0.1:5599
    protocols: []
`)
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 1)
	assert.False(t, fwd_list.IsEmpty())

	fwd1 := fwd_list.configPortForwardings["outbound.tcp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingTcp)
	assert.NotNil(t, fwd1)
	assert.Equal(t, fwd1.localListen, "127.0.0.1:3399")
	assert.Equal(t, fwd1.remoteConnect, "192.168.100.92:4499")
}

func TestConfigWithUdpIn(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:4499
    protocols: []
  inbound:
  - listen_port: 5580
    dial_address: 127.0.0.1:5599
    protocols: [udp]
`)
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 1)
	assert.False(t, fwd_list.IsEmpty())

	fwd1 := fwd_list.configPortForwardings["inbound.udp.5580.127.0.0.1:5599"].(ForwardConfigIncomingUdp)
	assert.NotNil(t, fwd1)
	assert.Equal(t, fwd1.forwardLocalAddress, "127.0.0.1:5599")
	assert.Equal(t, int(fwd1.port), 5580)
}

func TestConfigWithUdpOut(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:4499
    protocols: [udp]
  inbound:
  - listen_port: 5580
    dial_address: 127.0.0.1:5599
    protocols: []
`)
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 1)
	assert.False(t, fwd_list.IsEmpty())

	fwd1 := fwd_list.configPortForwardings["outbound.udp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingUdp)
	assert.NotNil(t, fwd1)
	assert.Equal(t, fwd1.localListen, "127.0.0.1:3399")
	assert.Equal(t, fwd1.remoteConnect, "192.168.100.92:4499")
}

func TestConfigWithMultipleMixed(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:4499
    protocols: [udp, tcp]
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:5499
    protocols: [tcp]
  inbound:
  - listen_port: 5580
    dial_address: 127.0.0.1:5599
    protocols: [tcp, udp]
  - listen_port: 5570
    dial_address: 127.0.0.1:5555
    protocols: [udp]
`)
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 6)
	assert.False(t, fwd_list.IsEmpty())

	assert.NotNil(t, fwd_list.configPortForwardings["outbound.udp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingUdp))
	assert.NotNil(t, fwd_list.configPortForwardings["outbound.tcp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingTcp))
	assert.NotNil(t, fwd_list.configPortForwardings["outbound.tcp.127.0.0.1:3399.192.168.100.92:5499"].(ForwardConfigOutgoingTcp))
	assert.NotNil(t, fwd_list.configPortForwardings["inbound.tcp.5580.127.0.0.1:5599"].(ForwardConfigIncomingTcp))
	assert.NotNil(t, fwd_list.configPortForwardings["inbound.udp.5580.127.0.0.1:5599"].(ForwardConfigIncomingUdp))
	assert.NotNil(t, fwd_list.configPortForwardings["inbound.udp.5570.127.0.0.1:5555"].(ForwardConfigIncomingUdp))
}

func TestConfigWithOverlappingRulesNoDuplicatesInResult(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:4499
    protocols: [udp, tcp, udp]
  - listen_address: 127.0.0.1:3399
    dial_address: 192.168.100.92:4499
    protocols: [tcp]
  inbound:
  - listen_port: 5580
    dial_address: 127.0.0.1:5599
    protocols: [tcp, udp]
  - listen_port: 5580
    dial_address: 127.0.0.1:5599
    protocols: [udp, udp]
`)
	assert.Nil(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	assert.Nil(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 4)
	assert.False(t, fwd_list.IsEmpty())

	assert.NotNil(t, fwd_list.configPortForwardings["outbound.udp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingUdp))
	assert.NotNil(t, fwd_list.configPortForwardings["outbound.tcp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingTcp))
	assert.NotNil(t, fwd_list.configPortForwardings["inbound.tcp.5580.127.0.0.1:5599"].(ForwardConfigIncomingTcp))
	assert.NotNil(t, fwd_list.configPortForwardings["inbound.udp.5580.127.0.0.1:5599"].(ForwardConfigIncomingUdp))
}
