//go:build !e2e_testing
// +build !e2e_testing

package udp

import (
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiPortConn(t *testing.T) {
	l := slog.New(slog.DiscardHandler)
	lo := netip.MustParseAddr("127.0.0.1")

	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer recv.Close()
	dst := recv.LocalAddr().(*net.UDPAddr).AddrPort()

	// Use the kernel to find a free base port
	base, err := NewListener(l, Settings{Listen: netip.AddrPortFrom(lo, 0), Batch: 1})
	require.NoError(t, err)
	defer base.Close()
	baseAddr, err := base.LocalAddr()
	require.NoError(t, err)

	const ports = 4
	mp, err := NewMultiPortConn(l, Settings{Listen: baseAddr}, ports, 1)
	if err != nil {
		t.Skipf("unable to bind consecutive ports after %d: %v", baseAddr.Port(), err)
	}
	defer mp.Close()
	assert.Equal(t, ports, mp.Ports())

	buf := make([]byte, 16)
	for i := uint16(0); i < ports; i++ {
		require.NoError(t, mp.WriteTo([]byte{byte(i)}, i, 0, dst, base))
		require.NoError(t, recv.SetReadDeadline(time.Now().Add(time.Second)))
		n, from, err := recv.ReadFromUDPAddrPort(buf)
		require.NoError(t, err)
		assert.Equal(t, []byte{byte(i)}, buf[:n])
		assert.Equal(t, baseAddr.Port()+i, from.Port())
	}
}

func TestNewMultiPortConnErrors(t *testing.T) {
	l := slog.New(slog.DiscardHandler)
	lo := netip.MustParseAddr("127.0.0.1")

	_, err := NewMultiPortConn(l, Settings{Listen: netip.AddrPortFrom(lo, 4242)}, 0, 1)
	assert.Error(t, err)

	_, err = NewMultiPortConn(l, Settings{Listen: netip.AddrPortFrom(lo, 65530)}, 10, 1)
	assert.Error(t, err)

	mp, err := NewMultiPortConn(l, Settings{Listen: netip.AddrPortFrom(lo, 4242)}, 1, 1)
	require.NoError(t, err)
	assert.Equal(t, 1, mp.Ports())
	assert.NoError(t, mp.Close())
}

func TestMultiPortConnQueues(t *testing.T) {
	l := slog.New(slog.DiscardHandler)
	lo := netip.MustParseAddr("127.0.0.1")

	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer recv.Close()
	dst := recv.LocalAddr().(*net.UDPAddr).AddrPort()

	base, err := NewListener(l, Settings{Listen: netip.AddrPortFrom(lo, 0), Multi: true, Batch: 1})
	require.NoError(t, err)
	defer base.Close()
	baseAddr, err := base.LocalAddr()
	require.NoError(t, err)

	const ports, queues = 3, 2
	mp, err := NewMultiPortConn(l, Settings{Listen: baseAddr}, ports, queues)
	if err != nil {
		t.Skipf("unable to bind consecutive ports after %d: %v", baseAddr.Port(), err)
	}
	defer mp.Close()

	// Each queue has its own socket per port, all bound to the same port
	assert.NotSame(t, mp.Conn(1, 0, base), mp.Conn(1, 1, base))
	assert.Same(t, base, mp.Conn(0, 1, base))
	assert.Same(t, base, mp.Conn(1, queues, base), "an unknown queue falls back to base")

	buf := make([]byte, 16)
	for q := range queues {
		require.NoError(t, mp.WriteTo([]byte{byte(q)}, 2, q, dst, base))
		require.NoError(t, recv.SetReadDeadline(time.Now().Add(time.Second)))
		n, from, err := recv.ReadFromUDPAddrPort(buf)
		require.NoError(t, err)
		assert.Equal(t, []byte{byte(q)}, buf[:n])
		assert.Equal(t, baseAddr.Port()+2, from.Port())
	}
}
