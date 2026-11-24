package udp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUDP records writes and lets the test inject reads
type fakeUDP struct {
	NoopConn
	mu     sync.Mutex
	writes []netip.AddrPort
	in     chan rxPacket
	done   chan struct{}
	once   sync.Once
}

type rxPacket struct {
	addr netip.AddrPort
	b    []byte
}

func newFakeUDP() *fakeUDP {
	return &fakeUDP{in: make(chan rxPacket, 16), done: make(chan struct{})}
}

func (f *fakeUDP) WriteTo(_ []byte, addr netip.AddrPort) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, addr)
	return nil
}

func (f *fakeUDP) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, addrs...)
	return len(bufs), nil
}

func (f *fakeUDP) ListenOut(r EncReader, flush func()) error {
	for {
		select {
		case p := <-f.in:
			r(p.addr, p.b)
			flush()
		case <-f.done:
			return net.ErrClosed
		}
	}
}

func (f *fakeUDP) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}

func (f *fakeUDP) udpWrites() []netip.AddrPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.AddrPort(nil), f.writes...)
}

type tcpNode struct {
	t     *TCPTransport
	conns []Conn
	udp   []*fakeUDP
	rx    chan rxPacket
}

func newTCPNode(t *testing.T, cfg string, routines int) *tcpNode {
	t.Helper()
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.LoadString(cfg))

	tr, err := NewTCPTransportFromConfig(l, c, netip.MustParseAddrPort("127.0.0.1:0"))
	require.NoError(t, err)
	require.NotNil(t, tr)

	n := &tcpNode{t: tr, rx: make(chan rxPacket, 64)}
	inner := make([]Conn, routines)
	for i := range inner {
		u := newFakeUDP()
		n.udp = append(n.udp, u)
		inner[i] = u
	}
	n.conns = tr.Wrap(inner)
	go func() {
		_ = n.conns[0].ListenOut(func(addr netip.AddrPort, b []byte) {
			n.rx <- rxPacket{addr: addr, b: append([]byte(nil), b...)}
		}, func() {})
	}()
	t.Cleanup(func() {
		for _, c := range n.conns {
			_ = c.Close()
		}
	})
	return n
}

func (n *tcpNode) addr() netip.AddrPort {
	return netip.MustParseAddrPort(n.t.ln.Addr().String())
}

func recvPacket(t *testing.T, ch chan rxPacket) rxPacket {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for packet")
		return rxPacket{}
	}
}

func TestTCPTransportDisabled(t *testing.T) {
	l := test.NewLogger()
	tr, err := NewTCPTransportFromConfig(l, config.NewC(l), netip.MustParseAddrPort("127.0.0.1:0"))
	require.NoError(t, err)
	assert.Nil(t, tr)
}

func TestTCPTransportRoundTrip(t *testing.T) {
	server := newTCPNode(t, "tcp:\n  listen: true\n", 2)
	client := newTCPNode(t, fmt.Sprintf("tcp:\n  remotes: [%q]\n", server.addr()), 2)

	// A write to a tcp.remotes address dials and arrives on the server's primary reader, from any routine
	require.NoError(t, client.conns[1].WriteTo([]byte("hello"), server.addr()))
	p := recvPacket(t, server.rx)
	assert.Equal(t, "hello", string(p.b))
	clientAddr := p.addr

	// The server replies to the address the packet came from, which routes back over the same connection
	require.NoError(t, server.conns[1].WriteTo([]byte("world"), clientAddr))
	p = recvPacket(t, client.rx)
	assert.Equal(t, "world", string(p.b))
	assert.Equal(t, server.addr(), p.addr)

	// Neither side leaked anything over UDP
	for _, u := range append(server.udp, client.udp...) {
		assert.Empty(t, u.udpWrites())
	}

	// Everything else still goes over UDP
	other := netip.MustParseAddrPort("192.0.2.1:4242")
	require.NoError(t, client.conns[0].WriteTo([]byte("udp"), other))
	assert.Equal(t, []netip.AddrPort{other}, client.udp[0].udpWrites())

	// UDP packets still reach the reader
	server.udp[0].in <- rxPacket{addr: other, b: []byte("from udp")}
	p = recvPacket(t, server.rx)
	assert.Equal(t, "from udp", string(p.b))
	assert.Equal(t, other, p.addr)
}

func TestTCPTransportWriteBatch(t *testing.T) {
	server := newTCPNode(t, "tcp:\n  listen: true\n", 1)
	client := newTCPNode(t, fmt.Sprintf("tcp:\n  remotes: [%q]\n", server.addr()), 1)

	u1 := netip.MustParseAddrPort("192.0.2.1:4242")
	u2 := netip.MustParseAddrPort("192.0.2.2:4242")
	n, err := client.conns[0].WriteBatch(
		[][]byte{[]byte("u1"), []byte("t1"), []byte("u2"), []byte("t2")},
		[]netip.AddrPort{u1, server.addr(), u2, server.addr()},
	)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, []netip.AddrPort{u1, u2}, client.udp[0].udpWrites())

	// Order is preserved within the connection
	assert.Equal(t, "t1", string(recvPacket(t, server.rx).b))
	assert.Equal(t, "t2", string(recvPacket(t, server.rx).b))
}

func TestTCPTransportRejectsBadFrames(t *testing.T) {
	server := newTCPNode(t, "tcp:\n  listen: true\n", 1)

	for _, length := range []uint16{0, MTU + 1} {
		conn, err := net.Dial("tcp", server.addr().String())
		require.NoError(t, err)
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], length)
		_, err = conn.Write(hdr[:])
		require.NoError(t, err)

		assertHungUp(t, conn)
		_ = conn.Close()
	}
	assert.Empty(t, server.rx)
}

func TestTCPTransportMaxConns(t *testing.T) {
	server := newTCPNode(t, "tcp:\n  listen: true\n  max_conns: 1\n", 1)

	c1, err := net.Dial("tcp", server.addr().String())
	require.NoError(t, err)
	defer c1.Close()
	frame := []byte{0, 1, 'a'}
	_, err = c1.Write(frame)
	require.NoError(t, err)
	recvPacket(t, server.rx)

	c2, err := net.Dial("tcp", server.addr().String())
	require.NoError(t, err)
	defer c2.Close()
	assertHungUp(t, c2)

	// Closing the first frees the slot
	require.NoError(t, c1.Close())
	require.Eventually(t, func() bool {
		server.t.peersMu.Lock()
		defer server.t.peersMu.Unlock()
		return server.t.inbound == 0
	}, 5*time.Second, 10*time.Millisecond)
}

// assertHungUp checks the server closed conn
func assertHungUp(t *testing.T, conn net.Conn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := conn.Read(make([]byte, 1))
	require.Error(t, err)
	var ne net.Error
	if errors.As(err, &ne) {
		assert.False(t, ne.Timeout(), "server did not close the connection")
	}
}

func TestTCPTransportRebindRedials(t *testing.T) {
	server := newTCPNode(t, "tcp:\n  listen: true\n", 1)
	client := newTCPNode(t, fmt.Sprintf("tcp:\n  remotes: [%q]\n", server.addr()), 1)

	require.NoError(t, client.conns[0].WriteTo([]byte("one"), server.addr()))
	first := recvPacket(t, server.rx).addr

	require.NoError(t, client.conns[0].Rebind())
	require.Eventually(t, func() bool { return client.t.peer(server.addr()) == nil }, 5*time.Second, 10*time.Millisecond)

	require.NoError(t, client.conns[0].WriteTo([]byte("two"), server.addr()))
	p := recvPacket(t, server.rx)
	assert.Equal(t, "two", string(p.b))
	assert.NotEqual(t, first, p.addr, "expected a new connection")
}

func TestTCPTransportResolvesHostnames(t *testing.T) {
	server := newTCPNode(t, "tcp:\n  listen: true\n", 1)
	client := newTCPNode(t, fmt.Sprintf("tcp:\n  remotes: [\"localhost:%d\", \"invalid.invalid:1\"]\n", server.addr().Port()), 1)

	// Resolution happens in the background, an unresolvable name does not hold up the rest
	require.Eventually(t, func() bool { return client.t.isRemote(server.addr()) }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, client.conns[0].WriteTo([]byte("hi"), server.addr()))
	assert.Equal(t, "hi", string(recvPacket(t, server.rx).b))
}

func TestTCPTransportNoDeliveryAfterClose(t *testing.T) {
	server := newTCPNode(t, "tcp:\n  listen: true\n", 1)
	conn, err := net.Dial("tcp", server.addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte{0, 1, 'a'})
	require.NoError(t, err)
	recvPacket(t, server.rx)

	require.NoError(t, server.t.Close())
	// Close waited for the readers, nothing can be delivered past this point
	_, _ = conn.Write([]byte{0, 1, 'b'})
	assertHungUp(t, conn)
	assert.Empty(t, server.rx)
}

func TestTCPTransportSustainedLoad(t *testing.T) {
	const writeTimeout = 500 * time.Millisecond
	// A slow reader that keeps up with each write but never lets the client's queue drain
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
			go func() {
				defer c.Close()
				buf := make([]byte, 64*1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					time.Sleep(time.Millisecond)
				}
			}()
		}
	}()

	server := netip.MustParseAddrPort(ln.Addr().String())
	client := newTCPNode(t, fmt.Sprintf("tcp:\n  remotes: [%q]\n", server), 1)
	client.t.writeTimeout = writeTimeout
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		pkt := make([]byte, 1200)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = client.conns[0].WriteTo(pkt, server)
		}
	}()

	<-accepted
	select {
	case <-accepted:
		t.Fatal("connection was re-established under sustained load")
	case <-time.After(5 * writeTimeout):
	}
}
