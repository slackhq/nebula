package port_forwarder

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
	"github.com/stretchr/testify/assert"
)

func doTestTcpCommunication(
	t *testing.T,
	msg string,
	senderConn net.Conn,
	receiverConn net.Conn,
) {
	data_sent := []byte(msg)
	n, err := senderConn.Write(data_sent)
	assert.Nil(t, err)
	assert.Equal(t, n, len(data_sent))

	buf := make([]byte, 100)
	n, err = receiverConn.Read(buf)
	assert.Nil(t, err)
	assert.Equal(t, n, len(data_sent))
	assert.Equal(t, data_sent, buf[:n])
}

func doTestTcpCommunicationFail(
	t *testing.T,
	msg string,
	senderConn net.Conn,
	receiverConn net.Conn,
) {
	data_sent := []byte(msg)
	n, err := senderConn.Write(data_sent)
	if err != nil {
		return
	}
	assert.Nil(t, err)
	assert.Equal(t, n, len(data_sent))

	buf := make([]byte, 100)
	_, err = receiverConn.Read(buf)
	assert.NotNil(t, err)
}

func TestTcpInOut2Clients(t *testing.T) {
	l := logrus.New()
	server, client := service.CreateTwoConnectedServices(t, 4247)
	defer client.Close()
	defer server.Close()

	server_pf, err := createPortForwarderFromConfigString(l, server, `
port_forwarding:
  inbound:
  - listen_port: 4495
    dial_address: 127.0.0.1:5595
    protocols: [tcp]
`)
	assert.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	client_pf, err := createPortForwarderFromConfigString(l, client, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3395
    dial_address: 10.0.0.1:4495
    protocols: [tcp]
`)
	assert.Nil(t, err)

	assert.Len(t, client_pf.portForwardings, 1)

	client_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:3395")
	assert.Nil(t, err)
	server_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:5595")
	assert.Nil(t, err)

	server_listen_conn, err := net.ListenTCP("tcp", server_conn_addr)
	assert.Nil(t, err)
	client1_conn, err := net.DialTCP("tcp", nil, client_conn_addr)
	assert.Nil(t, err)
	client1_server_side_conn, err := server_listen_conn.Accept()
	assert.Nil(t, err)
	client2_conn, err := net.DialTCP("tcp", nil, client_conn_addr)
	assert.Nil(t, err)
	client2_server_side_conn, err := server_listen_conn.Accept()
	assert.Nil(t, err)

	doTestTcpCommunication(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)
	doTestTcpCommunication(t, "Hello from client two side!",
		client2_conn, client2_server_side_conn)

	doTestTcpCommunication(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)
	doTestTcpCommunication(t, "Hello from server second side!",
		client2_server_side_conn, client2_conn)
	doTestTcpCommunication(t, "Hello from server third side!",
		client1_server_side_conn, client1_conn)

	doTestTcpCommunication(t, "Hello from client two side AGAIN!",
		client2_conn, client2_server_side_conn)

}

func TestTcpInOut1ClientConfigReload(t *testing.T) {
	l := logrus.New()
	server, client := service.CreateTwoConnectedServices(t, 4246)
	defer client.Close()
	defer server.Close()

	server_pf, err := createPortForwarderFromConfigString(l, server, `
port_forwarding:
  inbound:
  - listen_port: 4497
    dial_address: 127.0.0.1:5597
    protocols: [tcp]
`)
	assert.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	client_pf, err := createPortForwarderFromConfigString(l, client, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3397
    dial_address: 10.0.0.1:4497
    protocols: [tcp]
`)
	assert.Nil(t, err)

	assert.Len(t, client_pf.portForwardings, 1)

	client_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:3397")
	assert.Nil(t, err)
	server_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:5597")
	assert.Nil(t, err)

	server_listen_conn, err := net.ListenTCP("tcp", server_conn_addr)
	assert.Nil(t, err)
	client1_conn, err := net.DialTCP("tcp", nil, client_conn_addr)
	assert.Nil(t, err)
	client1_server_side_conn, err := server_listen_conn.Accept()
	assert.Nil(t, err)

	doTestTcpCommunication(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunication(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)
	doTestTcpCommunication(t, "Hello from server third side!",
		client1_server_side_conn, client1_conn)

	doTestTcpCommunication(t, "Hello from client one side AGAIN!",
		client1_conn, client1_server_side_conn)

	new_server_fwd_list, err := loadPortFwdConfigFromString(l, `
port_forwarding:
  inbound:
  - listen_port: 4496
    dial_address: 127.0.0.1:5596
    protocols: [tcp]
`)
	assert.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	new_client_fwd_list, err := loadPortFwdConfigFromString(l, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3396
    dial_address: 10.0.0.1:4496
    protocols: [tcp]
`)
	assert.Nil(t, err)

	err = client_pf.ApplyChangesByNewFwdList(new_client_fwd_list)
	assert.Nil(t, err)

	doTestTcpCommunicationFail(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunicationFail(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)

	err = server_pf.ApplyChangesByNewFwdList(new_server_fwd_list)
	assert.Nil(t, err)

	doTestTcpCommunicationFail(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunicationFail(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)
}

func TestTcpInOut1ClientConfigReload_inverseCloseOrder(t *testing.T) {
	l := logrus.New()
	server, client := service.CreateTwoConnectedServices(t, 4245)
	defer client.Close()
	defer server.Close()

	server_pf, err := createPortForwarderFromConfigString(l, server, `
port_forwarding:
  inbound:
  - listen_port: 4499
    dial_address: 127.0.0.1:5599
    protocols: [tcp]
`)
	assert.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	client_pf, err := createPortForwarderFromConfigString(l, client, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 10.0.0.1:4499
    protocols: [tcp]
`)
	assert.Nil(t, err)

	assert.Len(t, client_pf.portForwardings, 1)

	client_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:3399")
	assert.Nil(t, err)
	server_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:5599")
	assert.Nil(t, err)

	server_listen_conn, err := net.ListenTCP("tcp", server_conn_addr)
	assert.Nil(t, err)
	client1_conn, err := net.DialTCP("tcp", nil, client_conn_addr)
	assert.Nil(t, err)
	client1_server_side_conn, err := server_listen_conn.Accept()
	assert.Nil(t, err)

	doTestTcpCommunication(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunication(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)
	doTestTcpCommunication(t, "Hello from server third side!",
		client1_server_side_conn, client1_conn)

	doTestTcpCommunication(t, "Hello from client one side AGAIN!",
		client1_conn, client1_server_side_conn)

	new_server_fwd_list, err := loadPortFwdConfigFromString(l, `
port_forwarding:
  inbound:
  - listen_port: 4498
    dial_address: 127.0.0.1:5598
    protocols: [tcp]
`)
	assert.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	new_client_fwd_list, err := loadPortFwdConfigFromString(l, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3398
    dial_address: 10.0.0.1:4498
    protocols: [tcp]
`)
	assert.Nil(t, err)

	err = server_pf.ApplyChangesByNewFwdList(new_server_fwd_list)
	assert.Nil(t, err)

	doTestTcpCommunicationFail(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunicationFail(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)

	err = client_pf.ApplyChangesByNewFwdList(new_client_fwd_list)
	assert.Nil(t, err)

	doTestTcpCommunicationFail(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunicationFail(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)
}
