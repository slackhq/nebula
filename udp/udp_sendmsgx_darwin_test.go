//go:build !e2e_testing

package udp

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recvAll reads n datagrams from pc, or fails the test after a second without one.
func recvAll(t *testing.T, pc net.PacketConn, n int) []string {
	t.Helper()
	var got []string
	buf := make([]byte, 64)
	for len(got) < n {
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(time.Second)))
		l, _, err := pc.ReadFrom(buf)
		require.NoError(t, err, "after %d of %d datagrams", len(got), n)
		got = append(got, string(buf[:l]))
	}
	return got
}

// A batch longer than sendBatch reaches each peer whole and in order through sendmsg_x, without falling
// back to sendto: a run to one peer that spans two calls, then datagrams alternating between peers.
func TestWriteBatchSendsEachToItsPeer(t *testing.T) {
	for _, tc := range []struct{ name, listen string }{
		{"v4", "127.0.0.1"},
		{"v6", "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewListener(slog.New(slog.DiscardHandler), Settings{Listen: netip.AddrPortFrom(netip.MustParseAddr(tc.listen), 0)})
			require.NoError(t, err)
			defer c.Close()

			var peers [2]net.PacketConn
			var dsts [2]netip.AddrPort
			for i := range peers {
				peers[i], err = net.ListenPacket("udp", net.JoinHostPort(tc.listen, "0"))
				require.NoError(t, err)
				defer peers[i].Close()
				dsts[i] = netip.MustParseAddrPort(peers[i].LocalAddr().String())
			}

			const total = sendBatch*2 + 5
			bufs := make([][]byte, total)
			addrs := make([]netip.AddrPort, total)
			var want [2][]string
			for i := range bufs {
				bufs[i] = fmt.Appendf(nil, "pkt-%03d", i)
				p := i % 2
				if i < sendBatch+6 {
					p = 0
				}
				addrs[i] = dsts[p]
				want[p] = append(want[p], string(bufs[i]))
			}

			n, err := c.WriteBatch(bufs, addrs)
			require.NoError(t, err)
			assert.Equal(t, total, n)
			assert.False(t, c.(*StdConn).noSendmsgX.Load(), "fell back to sendto")
			for i := range peers {
				assert.Equal(t, want[i], recvAll(t, peers[i], len(want[i])))
			}
		})
	}
}

// Destinations that can't be sent to cost only their own packets: an IPv6 peer on an IPv4 socket is
// skipped before the call, and a broadcast address without SO_BROADCAST is refused by the kernel
// mid-batch. Neither stops the packets around it, delivers any twice, or turns sendmsg_x off.
func TestWriteBatchSkipsUnsendableDestinations(t *testing.T) {
	c, err := NewListener(slog.New(slog.DiscardHandler), Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0")})
	require.NoError(t, err)
	defer c.Close()

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()
	good := netip.MustParseAddrPort(peer.LocalAddr().String())
	bcast := netip.AddrPortFrom(netip.MustParseAddr("255.255.255.255"), good.Port())
	v6 := netip.MustParseAddrPort("[::1]:4242")

	addrs := []netip.AddrPort{good, bcast, bcast, good, v6, good, bcast}
	bufs := make([][]byte, len(addrs))
	for i := range bufs {
		bufs[i] = fmt.Appendf(nil, "pkt-%d", i)
	}

	n, err := c.WriteBatch(bufs, addrs)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.False(t, c.(*StdConn).noSendmsgX.Load(), "fell back to sendto")
	assert.Equal(t, []string{"pkt-0", "pkt-3", "pkt-5"}, recvAll(t, peer, 3))
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, _, err = peer.ReadFrom(make([]byte, 64))
	assert.Error(t, err, "a datagram arrived twice")
}

// A datagram the kernel refuses as its own fault (EMSGSIZE here, as ENOBUFS would be under a full
// interface queue) costs only itself, whether it fails after others in the same call (a short count) or
// first (the errno alone): the rest of its run still arrives, in order, and sendmsg_x stays on.
func TestWriteBatchLosesOnlyTheFailedDatagram(t *testing.T) {
	for _, tc := range []struct {
		name string
		big  int
	}{
		{"mid-call", 2},
		{"first", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewListener(slog.New(slog.DiscardHandler), Settings{Listen: netip.MustParseAddrPort("127.0.0.1:0")})
			require.NoError(t, err)
			defer c.Close()

			peer, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			defer peer.Close()
			dst := netip.MustParseAddrPort(peer.LocalAddr().String())

			bufs := make([][]byte, 5)
			addrs := make([]netip.AddrPort, len(bufs))
			var want []string
			for i := range bufs {
				addrs[i] = dst
				if i == tc.big {
					// Past the 65535-byte IP datagram limit, so the kernel can only refuse it.
					bufs[i] = make([]byte, 70000)
					continue
				}
				bufs[i] = fmt.Appendf(nil, "pkt-%d", i)
				want = append(want, string(bufs[i]))
			}

			n, err := c.WriteBatch(bufs, addrs)
			require.NoError(t, err)
			assert.Equal(t, len(want), n)
			assert.False(t, c.(*StdConn).noSendmsgX.Load(), "fell back to sendto")
			assert.Equal(t, want, recvAll(t, peer, len(want)))
		})
	}
}
