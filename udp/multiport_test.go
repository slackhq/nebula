//go:build !e2e_testing
// +build !e2e_testing

package udp

import (
	"bytes"
	"fmt"
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
		require.NoError(t, mp.Conn(i, 0, base).WriteTo([]byte{byte(i)}, dst))
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

	// Each queue sends through the port's one socket in its own way
	assert.NotSame(t, mp.Conn(1, 0, base), mp.Conn(1, 1, base))
	assert.Len(t, mp.sockets, ports-1)
	assert.Same(t, base, mp.Conn(0, 1, base))
	assert.Same(t, base, mp.Conn(1, queues, base), "an unknown queue falls back to base")

	buf := make([]byte, 16)
	for q := range queues {
		require.NoError(t, mp.Conn(2, q, base).WriteTo([]byte{byte(q)}, dst))
		require.NoError(t, recv.SetReadDeadline(time.Now().Add(time.Second)))
		n, from, err := recv.ReadFromUDPAddrPort(buf)
		require.NoError(t, err)
		assert.Equal(t, []byte{byte(q)}, buf[:n])
		assert.Equal(t, baseAddr.Port()+2, from.Port())
	}
}

func TestSendOnlyLogger(t *testing.T) {
	var buf bytes.Buffer
	l := sendOnlyLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	l.Info("info")
	l.Warn("warn")
	l.Error("error")
	l.With("k", "v").Info("with")
	out := buf.String()
	assert.Contains(t, out, `level=DEBUG msg=info`)
	assert.Contains(t, out, `level=DEBUG msg=warn`)
	assert.Contains(t, out, `level=ERROR msg=error`)
	assert.Contains(t, out, `level=DEBUG msg=with k=v`)

	// Demoted records are dropped by a handler that does not log debug
	buf.Reset()
	l = sendOnlyLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	l.Warn("warn")
	l.Error("error")
	assert.NotContains(t, buf.String(), "warn")
	assert.Contains(t, buf.String(), "level=ERROR")
}

func TestMultiPortConnQueuesWriteBatch(t *testing.T) {
	l := slog.New(slog.DiscardHandler)
	lo := netip.MustParseAddr("127.0.0.1")

	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer recv.Close()
	dst := recv.LocalAddr().(*net.UDPAddr).AddrPort()

	base, err := NewListener(l, Settings{Listen: netip.AddrPortFrom(lo, 0), Batch: 1})
	require.NoError(t, err)
	defer base.Close()
	baseAddr, err := base.LocalAddr()
	require.NoError(t, err)

	const ports, queues = 3, 4
	mp, err := NewMultiPortConn(l, Settings{Listen: baseAddr}, ports, queues)
	if err != nil {
		t.Skipf("unable to bind consecutive ports after %d: %v", baseAddr.Port(), err)
	}

	// Every queue batches through the port's one socket, from that port
	buf := make([]byte, 16)
	for q := range queues {
		n, err := mp.Conn(1, q, base).WriteBatch([][]byte{{byte(q)}, {byte(q + 10)}}, []netip.AddrPort{dst, dst})
		require.NoError(t, err)
		require.Equal(t, 2, n)
		for _, want := range []byte{byte(q), byte(q + 10)} {
			require.NoError(t, recv.SetReadDeadline(time.Now().Add(time.Second)))
			n, from, err := recv.ReadFromUDPAddrPort(buf)
			require.NoError(t, err)
			assert.Equal(t, []byte{want}, buf[:n])
			assert.Equal(t, baseAddr.Port()+1, from.Port())
		}
	}

	// The sockets are closed once, by the MultiPortConn
	assert.NoError(t, mp.Close())
}

// A port another socket holds, even one bound with SO_REUSEPORT like another nebula's listeners, fails to open
// instead of joining its group and taking a share of its traffic.
func TestNewMultiPortConnRefusesHeldPort(t *testing.T) {
	l := slog.New(slog.DiscardHandler)
	lo := netip.MustParseAddr("127.0.0.1")

	base, err := NewListener(l, Settings{Listen: netip.AddrPortFrom(lo, 0), Batch: 1})
	require.NoError(t, err)
	defer base.Close()
	baseAddr, err := base.LocalAddr()
	require.NoError(t, err)

	other, err := NewListener(l, Settings{Listen: netip.AddrPortFrom(lo, baseAddr.Port()+2), Multi: true, Batch: 1})
	if err != nil {
		t.Skipf("port %d is in use: %v", baseAddr.Port()+2, err)
	}
	defer other.Close()

	_, err = NewMultiPortConn(l, Settings{Listen: baseAddr}, 4, 8)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("port %d", baseAddr.Port()+2))
}
