//go:build !ios && !e2e_testing

package overlay

import (
	"os"
	"syscall"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// newSocketpairTun returns a tun on one end of a connected AF_UNIX datagram socketpair, which keeps
// datagram boundaries the way a utun control socket does, and the other end's fd.
// sndbuf is the tun end's send buffer, which caps the largest datagram it accepts.
func newSocketpairTun(t *testing.T, sndbuf int) (*tun, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	require.NoError(t, unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_SNDBUF, sndbuf))
	require.NoError(t, unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20))
	// A dropped datagram fails the read-back instead of hanging it.
	require.NoError(t, unix.SetsockoptTimeval(fds[1], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}))
	require.NoError(t, unix.SetNonblock(fds[0], true))
	f := os.NewFile(uintptr(fds[0]), "socketpair")
	t.Cleanup(func() {
		_ = f.Close()
		_ = unix.Close(fds[1])
	})
	return &tun{f: f, l: test.NewLogger()}, fds[1]
}

// testTunPkt returns packet i of size bytes, alternating IPv4 and IPv6, and the same packet as a utun
// datagram, behind its AF prefix.
func testTunPkt(i, size int) (pkt, wire []byte) {
	pkt = make([]byte, size)
	pkt[0] = 0x45
	af := byte(syscall.AF_INET)
	if i%2 == 1 {
		pkt[0] = 0x60
		af = syscall.AF_INET6
	}
	pkt[1] = byte(i)
	pkt[2] = byte(i >> 8)
	return pkt, append([]byte{0, 0, 0, af}, pkt...)
}

// TestTunQueueReadDrains pins that Read hands back every queued packet, AF prefix stripped and in
// order, capped at tunReadBatch per call, and doesn't wait for more once the queue is empty.
func TestTunQueueReadDrains(t *testing.T) {
	tn, w := newSocketpairTun(t, 1<<20)
	// An AF_UNIX datagram send is bounded by the receiver's buffer, here the tun's end.
	rc, err := tn.f.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, rc.Control(func(fd uintptr) {
		require.NoError(t, unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20))
	}))
	q := &tunQueue{t: tn, buf: make([]byte, tunReadArena)}
	total := tunReadBatch + 3
	var want [][]byte
	for i := range total {
		pkt, wire := testTunPkt(i, 60+i)
		_, err := unix.Write(w, wire)
		require.NoError(t, err)
		want = append(want, pkt)
	}

	var got [][]byte
	for _, size := range []int{tunReadBatch, 3} {
		pkts, err := q.Read()
		require.NoError(t, err)
		require.Len(t, pkts, size)
		for _, p := range pkts {
			got = append(got, p.Clone().Bytes)
		}
	}
	assert.Equal(t, want, got)
}

// TestTunQueueReadClipsPackets pins that each returned packet's capacity ends at its own bytes, so
// appending to one can't overwrite the next.
func TestTunQueueReadClipsPackets(t *testing.T) {
	tn, w := newSocketpairTun(t, 1<<20)
	q := &tunQueue{t: tn, buf: make([]byte, tunReadArena)}
	for i := range 2 {
		_, wire := testTunPkt(i, 100)
		_, err := unix.Write(w, wire)
		require.NoError(t, err)
	}
	pkts, err := q.Read()
	require.NoError(t, err)
	require.Len(t, pkts, 2)
	assert.Equal(t, len(pkts[0].Bytes), cap(pkts[0].Bytes))
}
