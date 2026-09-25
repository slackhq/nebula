//go:build !ios

package msgx

import (
	"bytes"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestAvailable pins that dlsym finds both calls in this macOS's libSystem, so the batched paths are live.
func TestAvailable(t *testing.T) {
	assert.True(t, Available())
}

// TestSendRecvRoundTrip pins the libSystem calling path end to end: a batch goes out through sendmsg_x in one
// call and comes back through recvmsg_x in one call, each message whole, in order, with Datalen set.
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
	sent, errno := Send(uintptr(fds[0]), hdrs, 0)
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
	got, errno := Recv(uintptr(fds[1]), rhdrs, 0)
	require.Zero(t, errno)
	require.Equal(t, n, got)
	for i := range n {
		l := int(rhdrs[i].Datalen)
		assert.Equal(t, want[i], bufs[i][:l], "message %d", i)
	}
}

// TestEmptyBatch pins that an empty batch is refused before it reaches the kernel.
func TestEmptyBatch(t *testing.T) {
	_, errno := Send(0, nil, 0)
	assert.Equal(t, syscall.EINVAL, errno)
	_, errno = Recv(0, nil, 0)
	assert.Equal(t, syscall.EINVAL, errno)
}
