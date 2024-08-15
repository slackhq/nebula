package port_forwarder

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/service"
	"github.com/stretchr/testify/assert"
)

func loadPortFwdConfigFromString(l *logrus.Logger, configStr string) (*PortForwardingList, error) {
	c := config.NewC(l)
	err := c.LoadString(configStr)
	if err != nil {
		return nil, err
	}

	fwd_list := NewPortForwardingList()
	err = ParseConfig(l, c, fwd_list)
	if err != nil {
		return nil, err
	}

	return &fwd_list, nil
}

func createPortForwarderFromConfigString(l *logrus.Logger, srv *service.Service, configStr string) (*PortForwardingService, error) {

	fwd_list, err := loadPortFwdConfigFromString(l, configStr)
	if err != nil {
		return nil, err
	}

	pf, err := ConstructFromInitialFwdList(srv, l, fwd_list)
	if err != nil {
		return nil, err
	}

	err = pf.Activate()
	if err != nil {
		return nil, err
	}

	return pf, nil
}

func doTestUdpCommunication(
	t *testing.T,
	msg string,
	senderConn *net.UDPConn,
	toAddr net.Addr,
	receiverConn *net.UDPConn,
) (senderAddr net.Addr) {
	data_sent := []byte(msg)
	var n int
	var err error
	if toAddr != nil {
		n, err = senderConn.WriteTo(data_sent, toAddr)
	} else {
		n, err = senderConn.Write(data_sent)
	}
	assert.Nil(t, err)
	assert.Equal(t, n, len(data_sent))

	buf := make([]byte, 100)
	n, senderAddr, err = receiverConn.ReadFrom(buf)
	assert.Nil(t, err)
	assert.Equal(t, n, len(data_sent))
	assert.Equal(t, data_sent, buf[:n])
	return
}

func TestUdpInOut2Clients(t *testing.T) {
	l := logrus.New()
	server, client := service.CreateTwoConnectedServices(t, 4244)
	defer client.Close()
	defer server.Close()

	server_pf, err := createPortForwarderFromConfigString(l, server, `
port_forwarding:
  inbound:
  - listen_port: 4499
    dial_address: 127.0.0.1:5599
    protocols: [udp]
`)
	assert.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	client_pf, err := createPortForwarderFromConfigString(l, client, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 10.0.0.1:4499
    protocols: [udp]
`)
	assert.Nil(t, err)

	assert.Len(t, client_pf.portForwardings, 1)

	client_conn_addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:3399")
	assert.Nil(t, err)
	server_conn_addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5599")
	assert.Nil(t, err)

	server_listen_conn, err := net.ListenUDP("udp", server_conn_addr)
	assert.Nil(t, err)
	client1_conn, err := net.DialUDP("udp", nil, client_conn_addr)
	assert.Nil(t, err)
	client2_conn, err := net.DialUDP("udp", nil, client_conn_addr)
	assert.Nil(t, err)

	client1_addr := doTestUdpCommunication(t, "Hello from client 1 side!",
		client1_conn, nil, server_listen_conn)
	assert.NotNil(t, client1_addr)
	client2_addr := doTestUdpCommunication(t, "Hello from client two side!",
		client2_conn, nil, server_listen_conn)
	assert.NotNil(t, client2_addr)

	doTestUdpCommunication(t, "Hello from server first side!",
		server_listen_conn, client1_addr, client1_conn)
	doTestUdpCommunication(t, "Hello from server second side!",
		server_listen_conn, client2_addr, client2_conn)
	doTestUdpCommunication(t, "Hello from server third side!",
		server_listen_conn, client1_addr, client1_conn)

	doTestUdpCommunication(t, "Hello from client two side AGAIN!",
		client2_conn, nil, server_listen_conn)

}
