package port_forwarder

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func createPortForwarderFromConfigString(t *testing.T, l *logrus.Logger, srv *service.Service, configStr string) (*PortForwardingService, error) {

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

	t.Cleanup(func() {
		pf.CloseAll()
	})

	return pf, nil
}

func doTestUdpCommunication(
	t *testing.T,
	msg string,
	senderConn *net.UDPConn,
	toAddr net.Addr,
	receiverConn <-chan Pair[[]byte, net.Addr],
) net.Addr {
	data_sent := []byte(msg)
	var n int
	var err error
	if toAddr != nil {
		n, err = senderConn.WriteTo(data_sent, toAddr)
	} else {
		n, err = senderConn.Write(data_sent)
	}
	require.Nil(t, err)
	assert.Equal(t, n, len(data_sent))

	pair := <-receiverConn
	require.Nil(t, err)
	assert.Equal(t, data_sent, pair.a)
	return pair.b
}

type Pair[A any, B any] struct {
	a A
	b B
}

func readUdpConnectionToChannel(conn *net.UDPConn) <-chan Pair[[]byte, net.Addr] {
	rcv_chan := make(chan Pair[[]byte, net.Addr])

	go func() {
		defer close(rcv_chan)
		for {
			buf := make([]byte, 100)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			rcv_chan <- Pair[[]byte, net.Addr]{buf[0:n], addr}
		}
	}()

	return rcv_chan
}

func TestUdpInOut2Clients(t *testing.T) {
	server, sl, client, cl := service.CreateTwoConnectedServices(t, 4244)

	server_pf, err := createPortForwarderFromConfigString(t, sl, server, `
port_forwarding:
  inbound:
  - listen_port: 4499
    dial_address: 127.0.0.1:5599
    protocols: [udp]
`)
	require.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	client_pf, err := createPortForwarderFromConfigString(t, cl, client, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 10.0.0.1:4499
    protocols: [udp]
`)
	require.Nil(t, err)

	assert.Len(t, client_pf.portForwardings, 1)

	client_conn_addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:3399")
	require.Nil(t, err)
	server_conn_addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5599")
	require.Nil(t, err)

	server_listen_conn, err := net.ListenUDP("udp", server_conn_addr)
	require.Nil(t, err)
	defer server_listen_conn.Close()
	server_listen_rcv_chan := readUdpConnectionToChannel(server_listen_conn)

	client1_conn, err := net.DialUDP("udp", nil, client_conn_addr)
	require.Nil(t, err)
	defer client1_conn.Close()
	client1_rcv_chan := readUdpConnectionToChannel(client1_conn)

	client2_conn, err := net.DialUDP("udp", nil, client_conn_addr)
	require.Nil(t, err)
	defer client2_conn.Close()
	client2_rcv_chan := readUdpConnectionToChannel(client2_conn)

	client1_addr := doTestUdpCommunication(t, "Hello from client 1 side!",
		client1_conn, nil, server_listen_rcv_chan)
	assert.NotNil(t, client1_addr)
	client2_addr := doTestUdpCommunication(t, "Hello from client two side!",
		client2_conn, nil, server_listen_rcv_chan)
	assert.NotNil(t, client2_addr)

	doTestUdpCommunication(t, "Hello from server first side!",
		server_listen_conn, client1_addr, client1_rcv_chan)
	doTestUdpCommunication(t, "Hello from server second side!",
		server_listen_conn, client2_addr, client2_rcv_chan)
	doTestUdpCommunication(t, "Hello from server third side!",
		server_listen_conn, client1_addr, client1_rcv_chan)

	doTestUdpCommunication(t, "Hello from client two side AGAIN!",
		client2_conn, nil, server_listen_rcv_chan)

}
