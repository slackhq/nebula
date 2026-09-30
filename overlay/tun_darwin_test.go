//go:build !ios && !e2e_testing

package overlay

import (
	"bytes"
	"os"
	"syscall"
	"testing"

	"github.com/slackhq/nebula/internal/msgx"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// newSocketpairTun returns a tun writing to one end of a connected AF_UNIX datagram socketpair, which
// takes sendmsg_x the way a utun control socket does, and the other end's fd for reading back.
// sndbuf is the writer's send buffer, which caps the largest datagram it accepts.
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
		t.Run(name, func(t *testing.T) {
			noTunSendX.Store(fallback)
			t.Cleanup(func() { noTunSendX.Store(false) })
			fn(t, fallback)
		})
	}
}

// TestTunWriteBatch pins that WriteBatch delivers every packet whole, in order and behind the right
// utun AF prefix, across several sendmsg_x calls, and returns nil.
func TestTunWriteBatch(t *testing.T) {
	forEachTunWritePath(t, func(t *testing.T, fallback bool) {
		tn, r := newSocketpairTun(t, 1<<20)

		var pkts, want [][]byte
		for i := range 3*msgx.Batch + 5 {
			p, w := testTunPkt(i, 60+i)
			pkts = append(pkts, p)
			want = append(want, w)
		}
		require.NoError(t, tn.WriteBatch(pkts))
		assert.Equal(t, fallback, noTunSendX.Load())
		readTunBack(t, r, want)
	})
}

// TestTunWriteBatchSkipsInvalid pins that an empty packet or one with no IP version is skipped
// without shifting the packets after it, and that the first such error is the one reported.
func TestTunWriteBatchSkipsInvalid(t *testing.T) {
	forEachTunWritePath(t, func(t *testing.T, fallback bool) {
		tn, r := newSocketpairTun(t, 1<<20)

		var pkts, want [][]byte
		for i := range 20 {
			p, w := testTunPkt(i, 60)
			pkts = append(pkts, p)
			want = append(want, w)
		}
		pkts = append(pkts[:10], append([][]byte{{0x10, 1, 2}, {}}, pkts[10:]...)...)

		err := tn.WriteBatch(pkts)
		assert.ErrorContains(t, err, "IP version")
		readTunBack(t, r, want)
	})
}

// TestTunWriteBatchOversize pins that a packet larger than the socket's send buffer drops only
// itself and is reported, whether sendmsg_x reaches it mid-call (a short count) or first (EMSGSIZE
// for the whole call). The send buffer is 1024 bytes and the oversize packet 2000.
func TestTunWriteBatchOversize(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   int
	}{
		{"mid-call", msgx.Batch + 6},
		{"first-in-call", msgx.Batch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachTunWritePath(t, func(t *testing.T, fallback bool) {
				tn, r := newSocketpairTun(t, 1024)

				var pkts, want [][]byte
				for i := range 2*msgx.Batch + 10 {
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
				err := tn.WriteBatch(pkts)
				assert.ErrorIs(t, err, unix.EMSGSIZE)
				assert.Equal(t, fallback, noTunSendX.Load())
				readTunBack(t, r, want)
			})
		})
	}
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

// TestTunRaisePendingPackets pins that the pending limit is set at SYSPROTO_CONTROL level after the receive buffer is
// grown to hold that many packets of the tun's MTU, and capped to what the buffer holds when it can't grow.
func TestTunRaisePendingPackets(t *testing.T) {
	type call struct{ level, opt, value int }
	stub := func(t *testing.T, rcvbuf int, failLevel, failOpt int) *[]call {
		set, get := tunSetsockoptInt, tunGetsockoptInt
		var calls []call
		tunSetsockoptInt = func(fd, level, opt, value int) error {
			calls = append(calls, call{level, opt, value})
			if level == failLevel && opt == failOpt {
				return unix.ENOBUFS
			}
			return nil
		}
		tunGetsockoptInt = func(fd, level, opt int) (int, error) { return rcvbuf, nil }
		t.Cleanup(func() { tunSetsockoptInt, tunGetsockoptInt = set, get })
		return &calls
	}
	for _, tc := range []struct {
		name      string
		rcvbuf    int
		mtu       int
		failLevel int
		failOpt   int
		want      []call
	}{
		{"grows rcvbuf first", 1 << 16, 9000, -1, -1, []call{
			{unix.SOL_SOCKET, unix.SO_RCVBUF, 64 * 9004},
			{2, 16, 64},
		}},
		{"rcvbuf already big enough", 1 << 20, 1300, -1, -1, []call{{2, 16, 64}}},
		{"rcvbuf refused caps pending", 10 * 1304, 1300, unix.SOL_SOCKET, unix.SO_RCVBUF, []call{
			{unix.SOL_SOCKET, unix.SO_RCVBUF, 64 * 1304},
			{2, 16, 10},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stub(t, tc.rcvbuf, tc.failLevel, tc.failOpt)
			tn, _ := newSocketpairTun(t, 1<<20)
			tn.DefaultMTU = tc.mtu
			_, err := tn.Queues(1)
			require.NoError(t, err)
			assert.Equal(t, tc.want, *calls)
		})
	}
}

func TestTun_WriteFraming(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	tn := &tun{f: w}

	for _, tc := range []struct {
		name string
		pkt  []byte
		af   byte
	}{
		// Literal families rather than syscall.AF_*, so a wrong constant in Write can't also fix the expectation.
		{"ipv4", []byte{0x45, 1, 2, 3, 4, 5}, 2},
		{"ipv6", []byte{0x60, 1, 2, 3, 4, 5}, 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := tn.Write(tc.pkt)
			require.NoError(t, err)
			require.Equal(t, len(tc.pkt), n)

			got := make([]byte, 64)
			n, err = r.Read(got)
			require.NoError(t, err)
			require.Equal(t, append([]byte{0, 0, 0, tc.af}, tc.pkt...), got[:n])
		})
	}

	_, err = tn.Write([]byte{0x10, 1, 2, 3})
	require.Error(t, err)
	_, err = tn.Write([]byte{})
	require.ErrorIs(t, err, syscall.EIO)

	// The rejected writes must not have put anything on the fd, so the next read sees only this packet.
	pkt := []byte{0x45, 9, 9}
	_, err = tn.Write(pkt)
	require.NoError(t, err)
	got := make([]byte, 64)
	n, err := r.Read(got)
	require.NoError(t, err)
	require.Equal(t, append([]byte{0, 0, 0, 2}, pkt...), got[:n])
}

func TestTun_ReadStripsHeader(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	tn := &tun{f: r}

	pkt := []byte{0x45, 1, 2, 3, 4, 5}
	_, err = w.Write(append([]byte{0, 0, 0, syscall.AF_INET}, pkt...))
	require.NoError(t, err)

	got := make([]byte, 64)
	n, err := tn.Read(got)
	require.NoError(t, err)
	require.Equal(t, pkt, got[:n])
}

func TestTun_ReadShort(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	tn := &tun{f: r}

	// Fewer bytes than the protocol header is not a packet.
	_, err = w.Write([]byte{0, 0})
	require.NoError(t, err)
	n, err := tn.Read(make([]byte, 64))
	require.NoError(t, err)
	require.Zero(t, n)

	// The next packet reads cleanly only if the short read consumed exactly what was written.
	pkt := []byte{0x45, 1, 2, 3}
	_, err = w.Write(append([]byte{0, 0, 0, syscall.AF_INET}, pkt...))
	require.NoError(t, err)
	got := make([]byte, 64)
	n, err = tn.Read(got)
	require.NoError(t, err)
	require.Equal(t, pkt, got[:n])
}

// A heap allocation per packet rarely shows in a short throughput run, only across GC pauses, so
// this pins Read and Write to zero allocations directly.
func TestTun_ReadWriteDoNotAllocate(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()
	defer w.Close()
	tw := &tun{f: w}
	tr := &tun{f: r}

	pkts := [][]byte{bytes.Repeat([]byte{0x45}, 1300), bytes.Repeat([]byte{0x60}, 1300)}
	buf := make([]byte, 1500)
	i := 0
	allocs := testing.AllocsPerRun(1000, func() {
		i++
		if _, err := tw.Write(pkts[i%len(pkts)]); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Read(buf); err != nil {
			t.Fatal(err)
		}
	})
	require.Zero(t, allocs)
}
