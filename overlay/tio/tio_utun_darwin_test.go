//go:build darwin && !ios

package tio

import (
	"bytes"
	"log/slog"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// newSocketpairUtun returns a Utun over one end of a connected AF_UNIX datagram socketpair, which
// takes sendmsg_x the way a utun control socket does, and the other end's fd for the test to use.
// sndbuf is the Utun's send buffer, which caps the largest datagram it accepts.
func newSocketpairUtun(t *testing.T, sndbuf int) (*Utun, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	require.NoError(t, unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_SNDBUF, sndbuf))
	// An AF_UNIX datagram send is bounded by the receiver's buffer, so size both ends' for the tests.
	require.NoError(t, unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20))
	require.NoError(t, unix.SetsockoptInt(fds[1], unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20))
	// A dropped datagram fails the read-back instead of hanging it.
	require.NoError(t, unix.SetsockoptTimeval(fds[1], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}))
	u, err := NewUtun(fds[0], slog.New(slog.DiscardHandler))
	if err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = u.Close()
		_ = unix.Close(fds[1])
	})
	return u, fds[1]
}

// testTunPkt returns packet i of size bytes, alternating IPv4 and IPv6, and the datagram the utun
// device should receive for it.
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

// readTunBack asserts r receives exactly want, in order.
func readTunBack(t *testing.T, r int, want [][]byte) {
	t.Helper()
	buf := make([]byte, 4096)
	for i, w := range want {
		n, _, err := unix.Recvfrom(r, buf, 0)
		require.NoError(t, err, "datagram %d", i)
		if !bytes.Equal(w, buf[:n]) {
			t.Fatalf("datagram %d: got % x, want % x", i, buf[:n], w)
		}
	}
	_, _, err := unix.Recvfrom(r, buf, unix.MSG_DONTWAIT)
	assert.ErrorIs(t, err, unix.EAGAIN, "extra datagrams delivered")
}

// forEachTunWritePath runs fn once over sendmsg_x and once over the per-packet writev fallback.
func forEachTunWritePath(t *testing.T, fn func(t *testing.T, fallback bool)) {
	for _, fallback := range []bool{false, true} {
		name := "sendmsg_x"
		if fallback {
			name = "writev"
		}
		t.Run(name, func(t *testing.T) { fn(t, fallback) })
	}
}

// TestUtunWriteBatch pins that WriteBatch delivers every packet whole, in order and behind the right
// utun AF prefix, across several sendmsg_x calls, and returns nil.
func TestUtunWriteBatch(t *testing.T) {
	forEachTunWritePath(t, func(t *testing.T, fallback bool) {
		u, r := newSocketpairUtun(t, 1<<20)
		u.noSendmsgX.Store(fallback)

		var pkts, want [][]byte
		for i := range 3*tunWriteBatch + 5 {
			p, w := testTunPkt(i, 60+i)
			pkts = append(pkts, p)
			want = append(want, w)
		}
		require.NoError(t, u.WriteBatch(pkts))
		assert.Equal(t, fallback, u.noSendmsgX.Load())
		readTunBack(t, r, want)
	})
}

// TestUtunWriteBatchSkipsInvalid pins that an empty packet or one with no IP version is skipped
// without shifting the packets after it, and that the first such error is the one reported.
func TestUtunWriteBatchSkipsInvalid(t *testing.T) {
	forEachTunWritePath(t, func(t *testing.T, fallback bool) {
		u, r := newSocketpairUtun(t, 1<<20)
		u.noSendmsgX.Store(fallback)

		var pkts, want [][]byte
		for i := range 20 {
			p, w := testTunPkt(i, 60)
			pkts = append(pkts, p)
			want = append(want, w)
		}
		pkts = append(pkts[:10], append([][]byte{{0x10, 1, 2}, {}}, pkts[10:]...)...)

		err := u.WriteBatch(pkts)
		assert.ErrorContains(t, err, "IP version")
		readTunBack(t, r, want)
	})
}

// TestUtunWriteBatchOversize pins that a packet larger than the socket's send buffer drops only
// itself and is reported, whether sendmsg_x reaches it mid-call (a short count) or first (EMSGSIZE
// for the whole call). The send buffer is 1024 bytes and the oversize packet 2000.
func TestUtunWriteBatchOversize(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   int
	}{
		{"mid-call", tunWriteBatch + 6},
		{"first-in-call", tunWriteBatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachTunWritePath(t, func(t *testing.T, fallback bool) {
				u, r := newSocketpairUtun(t, 1024)
				u.noSendmsgX.Store(fallback)

				var pkts, want [][]byte
				for i := range 2*tunWriteBatch + 10 {
					size := 100
					if i == tc.at {
						size = 2000
					}
					p, w := testTunPkt(i, size)
					pkts = append(pkts, p)
					if i != tc.at {
						want = append(want, w)
					}
				}
				err := u.WriteBatch(pkts)
				assert.ErrorIs(t, err, unix.EMSGSIZE)
				assert.Equal(t, fallback, u.noSendmsgX.Load())
				readTunBack(t, r, want)
			})
		})
	}
}

// TestUtunReadDrains pins that Read hands back every queued packet, AF prefix stripped and in
// order, capped at tunReadBatch per call, and doesn't wait for more once the queue is empty.
func TestUtunReadDrains(t *testing.T) {
	u, w := newSocketpairUtun(t, 1<<20)
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
		pkts, err := u.Read()
		require.NoError(t, err)
		require.Len(t, pkts, size)
		for _, p := range pkts {
			got = append(got, p.Clone().Bytes)
		}
	}
	assert.Equal(t, want, got)
}

// TestUtunReadClipsPackets pins that each returned packet's capacity ends at its own bytes, so
// appending to one can't overwrite the next.
func TestUtunReadClipsPackets(t *testing.T) {
	u, w := newSocketpairUtun(t, 1<<20)
	for i := range 2 {
		_, wire := testTunPkt(i, 100)
		_, err := unix.Write(w, wire)
		require.NoError(t, err)
	}
	pkts, err := u.Read()
	require.NoError(t, err)
	require.Len(t, pkts, 2)
	assert.Equal(t, len(pkts[0].Bytes), cap(pkts[0].Bytes))
}
