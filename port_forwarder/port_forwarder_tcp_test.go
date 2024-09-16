package port_forwarder

import (
	"fmt"
	"net"
	"testing"

	"github.com/slackhq/nebula/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startReadToChannel(receiverConn net.Conn) <-chan []byte {
	rcv_chan := make(chan []byte, 10)
	r := make(chan bool, 1)
	go func() {
		defer close(rcv_chan)
		r <- true
		for {
			buf := make([]byte, 100)
			n, err := receiverConn.Read(buf)
			if err != nil {
				break
			}
			rcv_chan <- buf[0:n]
		}
	}()
	<-r
	return rcv_chan
}

func doTestTcpCommunication(
	t *testing.T,
	msg string,
	senderConn net.Conn,
	receiverConn <-chan []byte,
) {
	var n int = 0
	var err error = nil
	data_sent := []byte(msg)
	var buf []byte = nil
	for {
		fmt.Println("sending ...")
		t.Log("sending ...")
		n, err = senderConn.Write(data_sent)
		require.Nil(t, err)
		assert.Equal(t, n, len(data_sent))

		fmt.Println("receiving ...")
		t.Log("receiving ...")
		var ok bool = false
		buf, ok = <-receiverConn
		if ok {
			break
		}
	}
	fmt.Println("DONE")
	t.Log("DONE")
	require.Nil(t, err)
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
	require.Nil(t, err)
	assert.Equal(t, n, len(data_sent))

	buf := make([]byte, 100)
	_, err = receiverConn.Read(buf)
	assert.NotNil(t, err)
}

func tcpListenerNAccept(t *testing.T, listener *net.TCPListener, n int) <-chan net.Conn {
	c := make(chan net.Conn, 1)
	r := make(chan bool, 1)
	go func() {
		defer close(c)
		r <- true
		for range n {
			conn, err := listener.Accept()
			require.Nil(t, err)
			c <- conn
		}
	}()

	<-r

	return c
}

func TestTcpInOut2Clients(t *testing.T) {
	server, sl, client, cl := service.CreateTwoConnectedServices(t, 4247)

	server_pf, err := createPortForwarderFromConfigString(t, sl, server, `
port_forwarding:
  inbound:
  - listen_port: 4495
    dial_address: 127.0.0.1:5595
    protocols: [tcp]
`)
	require.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	client_pf, err := createPortForwarderFromConfigString(t, cl, client, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3395
    dial_address: 10.0.0.1:4495
    protocols: [tcp]
`)
	require.Nil(t, err)

	assert.Len(t, client_pf.portForwardings, 1)

	client_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:3395")
	require.Nil(t, err)
	server_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:5595")
	require.Nil(t, err)

	server_listen_conn, err := net.ListenTCP("tcp", server_conn_addr)
	require.Nil(t, err)
	defer server_listen_conn.Close()
	server_listen_conn_accepts := tcpListenerNAccept(t, server_listen_conn, 2)

	client1_conn, err := net.DialTCP("tcp", nil, client_conn_addr)
	require.Nil(t, err)
	defer client1_conn.Close()

	client1_rcv_chan := startReadToChannel(client1_conn)
	client1_server_side_conn := <-server_listen_conn_accepts
	client1_server_side_rcv_chan := startReadToChannel(client1_server_side_conn)

	client2_conn, err := net.DialTCP("tcp", nil, client_conn_addr)
	require.Nil(t, err)
	defer client2_conn.Close()

	client2_rcv_chan := startReadToChannel(client2_conn)
	client2_server_side_conn := <-server_listen_conn_accepts
	client2_server_side_rcv_chan := startReadToChannel(client2_server_side_conn)

	doTestTcpCommunication(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_rcv_chan)
	doTestTcpCommunication(t, "Hello from client two side!",
		client2_conn, client2_server_side_rcv_chan)

	doTestTcpCommunication(t, "Hello from server first side!",
		client1_server_side_conn, client1_rcv_chan)
	doTestTcpCommunication(t, "Hello from server second side!",
		client2_server_side_conn, client2_rcv_chan)
	doTestTcpCommunication(t, "Hello from server third side!",
		client1_server_side_conn, client1_rcv_chan)

	doTestTcpCommunication(t, "Hello from client two side AGAIN!",
		client2_conn, client2_server_side_rcv_chan)

}

func TestTcpInOut1ClientConfigReload(t *testing.T) {
	server, sl, client, cl := service.CreateTwoConnectedServices(t, 4246)

	server_pf, err := createPortForwarderFromConfigString(t, sl, server, `
port_forwarding:
  inbound:
  - listen_port: 4497
    dial_address: 127.0.0.1:5597
    protocols: [tcp]
`)
	require.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	client_pf, err := createPortForwarderFromConfigString(t, cl, client, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3397
    dial_address: 10.0.0.1:4497
    protocols: [tcp]
`)
	require.Nil(t, err)

	assert.Len(t, client_pf.portForwardings, 1)

	client_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:3397")
	require.Nil(t, err)
	server_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:5597")
	require.Nil(t, err)

	server_listen_conn, err := net.ListenTCP("tcp", server_conn_addr)
	require.Nil(t, err)
	defer server_listen_conn.Close()

	server_listen_conn_accepts := tcpListenerNAccept(t, server_listen_conn, 1)

	client1_conn, err := net.DialTCP("tcp", nil, client_conn_addr)
	require.Nil(t, err)
	defer client1_conn.Close()
	client1_rcv_chan := startReadToChannel(client1_conn)

	client1_server_side_conn := <-server_listen_conn_accepts
	defer client1_server_side_conn.Close()
	client1_server_side_rcv_chan := startReadToChannel(client1_server_side_conn)

	doTestTcpCommunication(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_rcv_chan)

	doTestTcpCommunication(t, "Hello from server first side!",
		client1_server_side_conn, client1_rcv_chan)
	doTestTcpCommunication(t, "Hello from server third side!",
		client1_server_side_conn, client1_rcv_chan)

	doTestTcpCommunication(t, "Hello from client one side AGAIN!",
		client1_conn, client1_server_side_rcv_chan)

	new_server_fwd_list, err := loadPortFwdConfigFromString(sl, `
port_forwarding:
  inbound:
  - listen_port: 4496
    dial_address: 127.0.0.1:5596
    protocols: [tcp]
`)
	require.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	new_client_fwd_list, err := loadPortFwdConfigFromString(cl, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3396
    dial_address: 10.0.0.1:4496
    protocols: [tcp]
`)
	require.Nil(t, err)

	err = client_pf.ApplyChangesByNewFwdList(new_client_fwd_list)
	require.Nil(t, err)

	doTestTcpCommunicationFail(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunicationFail(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)

	err = server_pf.ApplyChangesByNewFwdList(new_server_fwd_list)
	require.Nil(t, err)

	doTestTcpCommunicationFail(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunicationFail(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)
}

func TestTcpInOut1ClientConfigReload_inverseCloseOrder(t *testing.T) {
	server, sl, client, cl := service.CreateTwoConnectedServices(t, 4245)

	server_pf, err := createPortForwarderFromConfigString(t, sl, server, `
port_forwarding:
  inbound:
  - listen_port: 4499
    dial_address: 127.0.0.1:5599
    protocols: [tcp]
`)
	require.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	client_pf, err := createPortForwarderFromConfigString(t, cl, client, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3399
    dial_address: 10.0.0.1:4499
    protocols: [tcp]
`)
	require.Nil(t, err)

	assert.Len(t, client_pf.portForwardings, 1)

	client_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:3399")
	require.Nil(t, err)
	server_conn_addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:5599")
	require.Nil(t, err)

	server_listen_conn, err := net.ListenTCP("tcp", server_conn_addr)
	require.Nil(t, err)
	defer server_listen_conn.Close()
	server_listen_conn_accepts := tcpListenerNAccept(t, server_listen_conn, 1)

	client1_conn, err := net.DialTCP("tcp", nil, client_conn_addr)
	require.Nil(t, err)
	defer client1_conn.Close()
	client1_rcv_chan := startReadToChannel(client1_conn)

	client1_server_side_conn := <-server_listen_conn_accepts
	defer client1_server_side_conn.Close()
	client1_server_side_rcv_chan := startReadToChannel(client1_server_side_conn)

	doTestTcpCommunication(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_rcv_chan)

	doTestTcpCommunication(t, "Hello from server first side!",
		client1_server_side_conn, client1_rcv_chan)
	doTestTcpCommunication(t, "Hello from server third side!",
		client1_server_side_conn, client1_rcv_chan)

	doTestTcpCommunication(t, "Hello from client one side AGAIN!",
		client1_conn, client1_server_side_rcv_chan)

	new_server_fwd_list, err := loadPortFwdConfigFromString(sl, `
port_forwarding:
  inbound:
  - listen_port: 4498
    dial_address: 127.0.0.1:5598
    protocols: [tcp]
`)
	require.Nil(t, err)

	assert.Len(t, server_pf.portForwardings, 1)

	new_client_fwd_list, err := loadPortFwdConfigFromString(cl, `
port_forwarding:
  outbound:
  - listen_address: 127.0.0.1:3398
    dial_address: 10.0.0.1:4498
    protocols: [tcp]
`)
	require.Nil(t, err)

	err = server_pf.ApplyChangesByNewFwdList(new_server_fwd_list)
	require.Nil(t, err)

	doTestTcpCommunicationFail(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunicationFail(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)

	err = client_pf.ApplyChangesByNewFwdList(new_client_fwd_list)
	require.Nil(t, err)

	doTestTcpCommunicationFail(t, "Hello from client 1 side!",
		client1_conn, client1_server_side_conn)

	doTestTcpCommunicationFail(t, "Hello from server first side!",
		client1_server_side_conn, client1_conn)
}
