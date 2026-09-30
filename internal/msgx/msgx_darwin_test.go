package msgx

import (
	"bytes"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestHdrLayout pins Hdr to struct msghdr_x's LP64 layout: 56 bytes, Datalen last at 48.
func TestHdrLayout(t *testing.T) {
	var h Hdr
	assert.EqualValues(t, 56, unsafe.Sizeof(h))
	assert.EqualValues(t, 48, unsafe.Offsetof(h.Datalen))
}

// TestSendRecvRoundTrip sends a batch through sendmsg_x in one call and reads it back through recvmsg_x in one
// call, each message whole, in order, with Datalen set.
func TestSendRecvRoundTrip(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	// A dropped datagram fails the receive instead of hanging it.
	require.NoError(t, unix.SetsockoptTimeval(fds[1], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}))

	const n = 5
	var want [n][]byte
	var iovs [n]unix.Iovec
	hdrs := make([]Hdr, n)
	for i := range n {
		want[i] = bytes.Repeat([]byte{byte(i + 1)}, 10+i)
		iovs[i] = unix.Iovec{Base: &want[i][0]}
		iovs[i].SetLen(len(want[i]))
		hdrs[i] = Hdr{Iov: &iovs[i], Iovlen: 1}
	}
	sent, errno := Send(uintptr(fds[0]), hdrs)
	require.Zero(t, errno)
	require.Equal(t, n, sent)

	var bufs [n + 1][64]byte
	var riovs [n + 1]unix.Iovec
	rhdrs := make([]Hdr, n+1)
	for i := range rhdrs {
		riovs[i] = unix.Iovec{Base: &bufs[i][0]}
		riovs[i].SetLen(len(bufs[i]))
		rhdrs[i] = Hdr{Iov: &riovs[i], Iovlen: 1}
	}
	got, errno := Recv(uintptr(fds[1]), rhdrs)
	require.Zero(t, errno)
	require.Equal(t, n, got)
	for i := range n {
		l := int(rhdrs[i].Datalen)
		assert.Equal(t, want[i], bufs[i][:l], "message %d", i)
	}
}

// TestEmptyBatch pins that an empty batch is refused before it reaches the kernel.
func TestEmptyBatch(t *testing.T) {
	_, errno := Send(0, nil)
	assert.Equal(t, syscall.EINVAL, errno)
	_, errno = Recv(0, nil)
	assert.Equal(t, syscall.EINVAL, errno)
}

func TestUnsupported(t *testing.T) {
	for _, e := range []syscall.Errno{syscall.ENOSYS, syscall.EPERM, syscall.EOPNOTSUPP} {
		assert.True(t, Unsupported(e), "%v", e)
	}
	for _, e := range []syscall.Errno{0, syscall.EAGAIN, syscall.ENOBUFS, syscall.EINVAL} {
		assert.False(t, Unsupported(e), "%v", e)
	}
}
