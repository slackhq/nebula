//go:build !ios && !e2e_testing

package overlay

import (
	"bytes"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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

// forEachTunReadPath runs fn once over recvmsg_x and once over the per-packet readv drain.
func forEachTunReadPath(t *testing.T, fn func(t *testing.T, newQ func(*tun) *tunQueue)) {
	for _, recvX := range []bool{true, false} {
		name := "recvmsg_x"
		if !recvX {
			name = "readv"
		}
		t.Run(name, func(t *testing.T) {
			fn(t, func(tn *tun) *tunQueue {
				q := newTunQueue(tn)
				if !recvX {
					q.x = nil
				}
				return q
			})
		})
	}
}

// writeTunPkts writes n test packets of size bytes to the peer end w and returns the packets the tun should hand back
// for them.
func writeTunPkts(t *testing.T, w, n, size int) [][]byte {
	t.Helper()
	var want [][]byte
	for i := range n {
		pkt, wire := testTunPkt(i, size+i)
		_, err := unix.Write(w, wire)
		require.NoError(t, err)
		want = append(want, pkt)
	}
	return want
}

// newReadTun is newSocketpairTun with the tun's receive buffer big enough for every test burst, since an AF_UNIX
// datagram send is bounded by the receiver's buffer, and the writer's send buffer big enough for the largest IP packet.
func newReadTun(t *testing.T) (*tun, int) {
	t.Helper()
	tn, w := newSocketpairTun(t, 1<<20)
	require.NoError(t, unix.SetsockoptInt(w, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<18))
	rc, err := tn.f.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, rc.Control(func(fd uintptr) {
		require.NoError(t, unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20))
	}))
	return tn, w
}

// readTunPkts calls q.Read once per entry of sizes, requires each to return that many packets, and returns copies of
// them all.
func readTunPkts(t *testing.T, q *tunQueue, sizes ...int) [][]byte {
	t.Helper()
	var got [][]byte
	for _, size := range sizes {
		pkts, err := q.Read()
		require.NoError(t, err)
		require.Len(t, pkts, size)
		for _, p := range pkts {
			got = append(got, p.Clone().Bytes)
		}
	}
	return got
}

// stubTunRecvmsgX swaps tunRecvmsgX for fn until the test ends and counts its calls. fn gets the real msgx.Recv to
// delegate to.
func stubTunRecvmsgX(t *testing.T, fn func(sys func(uintptr, []msgx.Hdr) (int, syscall.Errno), fd uintptr, hdrs []msgx.Hdr) (int, syscall.Errno)) *atomic.Int64 {
	t.Helper()
	sys := tunRecvmsgX
	var calls atomic.Int64
	tunRecvmsgX = func(fd uintptr, hdrs []msgx.Hdr) (int, syscall.Errno) {
		calls.Add(1)
		return fn(sys, fd, hdrs)
	}
	t.Cleanup(func() { tunRecvmsgX = sys })
	return &calls
}

// TestTunQueueReadDrains pins that Read hands back every queued packet, AF prefix stripped and in order, capped at
// tunReadBatch per call, and doesn't wait for more once the queue is empty.
func TestTunQueueReadDrains(t *testing.T) {
	forEachTunReadPath(t, func(t *testing.T, newQ func(*tun) *tunQueue) {
		tn, w := newReadTun(t)
		q := newQ(tn)
		want := writeTunPkts(t, w, tunReadBatch+3, 60)
		assert.Equal(t, want, readTunPkts(t, q, tunReadBatch, 3))
	})
}

// TestTunQueueReadUsesRecvX pins that a burst is read with one recvmsg_x, not one call per packet.
func TestTunQueueReadUsesRecvX(t *testing.T) {
	calls := stubTunRecvmsgX(t, func(sys func(uintptr, []msgx.Hdr) (int, syscall.Errno), fd uintptr, hdrs []msgx.Hdr) (int, syscall.Errno) {
		return sys(fd, hdrs)
	})
	tn, w := newReadTun(t)
	q := newTunQueue(tn)
	want := writeTunPkts(t, w, 10, 60)
	assert.Equal(t, want, readTunPkts(t, q, 10))
	assert.EqualValues(t, 1, calls.Load())
	assert.NotNil(t, q.x)
}

// TestTunQueueReadLargePackets pins that packets up to the largest IP packet come back whole, which on the recvmsg_x
// path means each lands in its own slot and none spills into the next.
func TestTunQueueReadLargePackets(t *testing.T) {
	forEachTunReadPath(t, func(t *testing.T, newQ func(*tun) *tunQueue) {
		tn, w := newReadTun(t)
		q := newQ(tn)
		var want [][]byte
		for i, size := range []int{65535, 1, 9001, 65535} {
			pkt, wire := testTunPkt(i, max(size, 3))
			pkt, wire = pkt[:size], wire[:4+size]
			_, err := unix.Write(w, wire)
			require.NoError(t, err)
			want = append(want, pkt)
		}
		assert.Equal(t, want, readTunPkts(t, q, 4))
	})
}

// TestTunQueueReadClipsPackets pins that each returned packet's capacity ends at its own bytes, so appending to one
// can't overwrite the next.
func TestTunQueueReadClipsPackets(t *testing.T) {
	forEachTunReadPath(t, func(t *testing.T, newQ func(*tun) *tunQueue) {
		tn, w := newSocketpairTun(t, 1<<20)
		q := newQ(tn)
		writeTunPkts(t, w, 2, 100)
		pkts, err := q.Read()
		require.NoError(t, err)
		require.Len(t, pkts, 2)
		assert.Equal(t, len(pkts[0].Bytes), cap(pkts[0].Bytes))
		assert.Equal(t, len(pkts[1].Bytes), cap(pkts[1].Bytes))
	})
}

// TestTunQueueReadDoesNotAllocate pins both read paths to zero allocations per Read once the queue exists.
func TestTunQueueReadDoesNotAllocate(t *testing.T) {
	forEachTunReadPath(t, func(t *testing.T, newQ func(*tun) *tunQueue) {
		tn, w := newReadTun(t)
		q := newQ(tn)
		_, wire := testTunPkt(0, 1300)
		allocs := testing.AllocsPerRun(1000, func() {
			if _, err := unix.Write(w, wire); err != nil {
				t.Fatal(err)
			}
			if pkts, err := q.Read(); err != nil || len(pkts) != 1 {
				t.Fatalf("read %d packets: %v", len(pkts), err)
			}
		})
		assert.Zero(t, allocs)
	})
}

// TestTunQueueReadXRefused pins that recvmsg_x being refused turns it off for good, and that the same Read still
// hands back the queued packets through readv.
func TestTunQueueReadXRefused(t *testing.T) {
	for _, errno := range []syscall.Errno{unix.ENOSYS, unix.EPERM, unix.EOPNOTSUPP, unix.EINVAL} {
		t.Run(errno.Error(), func(t *testing.T) {
			calls := stubTunRecvmsgX(t, func(func(uintptr, []msgx.Hdr) (int, syscall.Errno), uintptr, []msgx.Hdr) (int, syscall.Errno) {
				return 0, errno
			})
			tn, w := newReadTun(t)
			q := newTunQueue(tn)
			want := writeTunPkts(t, w, 5, 60)
			assert.Equal(t, want, readTunPkts(t, q, 5))
			assert.Nil(t, q.x)
			assert.EqualValues(t, 1, calls.Load())

			want = writeTunPkts(t, w, 2, 60)
			assert.Equal(t, want, readTunPkts(t, q, 2))
			assert.EqualValues(t, 1, calls.Load(), "recvmsg_x was tried again after it was refused")
		})
	}
}

// TestTunQueueReadXTransientError pins that an error from recvmsg_x that doesn't mean it is refused leaves this Read
// to readv but keeps recvmsg_x on for the next.
func TestTunQueueReadXTransientError(t *testing.T) {
	var failed atomic.Bool
	calls := stubTunRecvmsgX(t, func(sys func(uintptr, []msgx.Hdr) (int, syscall.Errno), fd uintptr, hdrs []msgx.Hdr) (int, syscall.Errno) {
		if !failed.Swap(true) {
			return 0, unix.ENOBUFS
		}
		return sys(fd, hdrs)
	})
	tn, w := newReadTun(t)
	q := newTunQueue(tn)
	want := writeTunPkts(t, w, 3, 60)
	assert.Equal(t, want, readTunPkts(t, q, 3))
	assert.NotNil(t, q.x)
	assert.EqualValues(t, 1, calls.Load())

	want = writeTunPkts(t, w, 2, 60)
	assert.Equal(t, want, readTunPkts(t, q, 2))
	assert.EqualValues(t, 2, calls.Load(), "recvmsg_x wasn't tried again after a transient error")
}

// TestTunQueueReadXParks pins that EAGAIN from recvmsg_x parks the Read until the utun is readable, rather than
// falling back or returning an empty batch.
func TestTunQueueReadXParks(t *testing.T) {
	var failed atomic.Bool
	calls := stubTunRecvmsgX(t, func(sys func(uintptr, []msgx.Hdr) (int, syscall.Errno), fd uintptr, hdrs []msgx.Hdr) (int, syscall.Errno) {
		if !failed.Swap(true) {
			return 0, unix.EAGAIN
		}
		return sys(fd, hdrs)
	})
	tn, w := newReadTun(t)
	q := newTunQueue(tn)
	// A real EAGAIN means nothing is queued, so the packet arrives only once Read has parked. One packet, so the
	// wakeup can't split it across Reads.
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(50 * time.Millisecond)
		_, wire := testTunPkt(0, 60)
		_, _ = unix.Write(w, wire)
	}()
	t.Cleanup(func() { <-done })
	pkt, _ := testTunPkt(0, 60)
	assert.Equal(t, [][]byte{pkt}, readTunPkts(t, q, 1))
	assert.NotNil(t, q.x)
	// A spurious wakeup costs another EAGAIN, so only a floor.
	assert.GreaterOrEqual(t, calls.Load(), int64(2))
}

// TestTunQueueReadXBadBatch pins that a recvmsg_x batch no intact header could produce turns recvmsg_x off for good
// and hands the Read to readv. The stub reports a bad batch without taking any packets, so readv then reads them all.
func TestTunQueueReadXBadBatch(t *testing.T) {
	v4 := [4]byte{3: syscall.AF_INET}
	for _, tc := range []struct {
		name string
		mess func(x *tunRecvX) int
	}{
		{"too many", func(x *tunRecvX) int {
			for i := range x.hdrs {
				x.hdrs[i].Datalen, x.heads[i] = 64, v4
			}
			return len(x.hdrs) + 1
		}},
		{"past the buffer", func(x *tunRecvX) int {
			x.hdrs[0].Datalen, x.heads[0] = 4+tunRecvXSlot+1, v4
			return 1
		}},
		{"bad AF prefix", func(x *tunRecvX) int {
			x.hdrs[0].Datalen, x.heads[0] = 64, [4]byte{syscall.AF_INET}
			return 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var q *tunQueue
			stubTunRecvmsgX(t, func(func(uintptr, []msgx.Hdr) (int, syscall.Errno), uintptr, []msgx.Hdr) (int, syscall.Errno) {
				return tc.mess(q.x), 0
			})
			tn, w := newReadTun(t)
			q = newTunQueue(tn)
			want := writeTunPkts(t, w, 4, 60)
			assert.Equal(t, want, readTunPkts(t, q, 4))
			assert.Nil(t, q.x)
		})
	}
}

// TestTunRecvXCheck pins which recvmsg_x batches tunRecvXCheck accepts.
func TestTunRecvXCheck(t *testing.T) {
	const slot = 1000
	v4, v6 := [4]byte{3: syscall.AF_INET}, [4]byte{3: syscall.AF_INET6}
	good := func() ([]msgx.Hdr, [][4]byte) {
		hdrs := make([]msgx.Hdr, 4)
		heads := make([][4]byte, 4)
		for i := range hdrs {
			hdrs[i].Datalen = uint64(4 + 20 + i)
			heads[i] = v4
			if i%2 == 1 {
				heads[i] = v6
			}
		}
		return hdrs, heads
	}
	for _, tc := range []struct {
		name string
		n    int
		mess func(hdrs []msgx.Hdr, heads [][4]byte)
		ok   bool
	}{
		{"all", 4, nil, true},
		{"none", 0, nil, true},
		{"prefix", 2, nil, true},
		{"garbage past n is ignored", 2, func(h []msgx.Hdr, hd [][4]byte) { h[3].Datalen, hd[3] = 1<<40, [4]byte{9} }, true},
		{"just the AF prefix", 1, func(h []msgx.Hdr, _ [][4]byte) { h[0].Datalen = 4 }, true},
		{"fills the slot", 1, func(h []msgx.Hdr, _ [][4]byte) { h[0].Datalen = 4 + slot }, true},
		{"more than headers", 5, nil, false},
		{"negative", -1, nil, false},
		{"past the slot", 2, func(h []msgx.Hdr, _ [][4]byte) { h[1].Datalen = 4 + slot + 1 }, false},
		{"shorter than the AF prefix", 1, func(h []msgx.Hdr, _ [][4]byte) { h[0].Datalen = 3 }, false},
		{"truncated", 3, func(h []msgx.Hdr, _ [][4]byte) { h[2].Flags = unix.MSG_TRUNC }, false},
		{"zero AF prefix", 1, func(_ []msgx.Hdr, hd [][4]byte) { hd[0] = [4]byte{} }, false},
		{"host order AF prefix", 1, func(_ []msgx.Hdr, hd [][4]byte) { hd[0] = [4]byte{syscall.AF_INET} }, false},
		{"other AF", 2, func(_ []msgx.Hdr, hd [][4]byte) { hd[1] = [4]byte{3: syscall.AF_UNIX} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdrs, heads := good()
			if tc.mess != nil {
				tc.mess(hdrs, heads)
			}
			err := tunRecvXCheck(tc.n, hdrs, heads, slot)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestTunRecvXRefused pins which recvmsg_x errnos turn it off for good.
func TestTunRecvXRefused(t *testing.T) {
	for _, errno := range []syscall.Errno{unix.ENOSYS, unix.EPERM, unix.EOPNOTSUPP, unix.EINVAL, unix.EMSGSIZE} {
		assert.True(t, tunRecvXRefused(errno), "%v", errno)
	}
	for _, errno := range []syscall.Errno{0, unix.EAGAIN, unix.EINTR, unix.ENOBUFS, unix.ENOMEM, unix.EBADF, unix.ENOTCONN} {
		assert.False(t, tunRecvXRefused(errno), "%v", errno)
	}
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
