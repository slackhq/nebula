package port_forwarder

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptyConfig(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString("bla:")
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

	assert.Empty(t, fwd_list.configPortForwardings)
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
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

	assert.Empty(t, fwd_list.configPortForwardings)
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
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

	assert.Empty(t, fwd_list.configPortForwardings)
	assert.True(t, fwd_list.IsEmpty())
}

func TestConfigWithNoProtocols_missing_in_out(t *testing.T) {
	l := logrus.New()
	c := config.NewC(l)
	err := c.LoadString(`
port_forwarding:
`)
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

	assert.Empty(t, fwd_list.configPortForwardings)
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
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 1)
	assert.False(t, fwd_list.IsEmpty())

	fwd1 := fwd_list.configPortForwardings["inbound.tcp.5580.127.0.0.1:5599"].(ForwardConfigIncomingTcp)
	assert.NotNil(t, fwd1)
	assert.Equal(t, "127.0.0.1:5599", fwd1.forwardLocalAddress)
	assert.Equal(t, 5580, int(fwd1.port))
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
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 1)
	assert.False(t, fwd_list.IsEmpty())

	fwd1 := fwd_list.configPortForwardings["outbound.tcp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingTcp)
	assert.NotNil(t, fwd1)
	assert.Equal(t, "127.0.0.1:3399", fwd1.localListen)
	assert.Equal(t, "192.168.100.92:4499", fwd1.remoteConnect)
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
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 1)
	assert.False(t, fwd_list.IsEmpty())

	fwd1 := fwd_list.configPortForwardings["inbound.udp.5580.127.0.0.1:5599"].(ForwardConfigIncomingUdp)
	assert.NotNil(t, fwd1)
	assert.Equal(t, "127.0.0.1:5599", fwd1.forwardLocalAddress)
	assert.Equal(t, 5580, int(fwd1.port))
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
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 1)
	assert.False(t, fwd_list.IsEmpty())

	fwd1 := fwd_list.configPortForwardings["outbound.udp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingUdp)
	assert.NotNil(t, fwd1)
	assert.Equal(t, "127.0.0.1:3399", fwd1.localListen)
	assert.Equal(t, "192.168.100.92:4499", fwd1.remoteConnect)
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
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

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
	require.NoError(t, err)

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	require.NoError(t, err)

	assert.Len(t, fwd_list.configPortForwardings, 4)
	assert.False(t, fwd_list.IsEmpty())

	assert.NotNil(t, fwd_list.configPortForwardings["outbound.udp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingUdp))
	assert.NotNil(t, fwd_list.configPortForwardings["outbound.tcp.127.0.0.1:3399.192.168.100.92:4499"].(ForwardConfigOutgoingTcp))
	assert.NotNil(t, fwd_list.configPortForwardings["inbound.tcp.5580.127.0.0.1:5599"].(ForwardConfigIncomingTcp))
	assert.NotNil(t, fwd_list.configPortForwardings["inbound.udp.5580.127.0.0.1:5599"].(ForwardConfigIncomingUdp))
}
