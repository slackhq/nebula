// Package msgx calls xnu's private batched socket calls, sendmsg_x and recvmsg_x, which move many datagrams per
// syscall. They are not public API, so a kernel or sandbox may refuse them; callers fall back to one datagram per
// syscall when Unsupported reports that.
package msgx

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Batch is the most messages the callers hand one sendmsg_x or recvmsg_x call.
const Batch = 64

// Hdr mirrors xnu's struct msghdr_x (bsd/sys/socket_private.h), which the SDK doesn't ship. recvmsg_x reports each
// message's length in Datalen rather than in its return value.
type Hdr struct {
	Name       *byte
	Namelen    uint32
	Iov        *unix.Iovec
	Iovlen     int32
	Control    *byte
	Controllen uint32
	Flags      int32
	Datalen    uint64
}

// Send passes hdrs to sendmsg_x on fd and returns how many messages the kernel took. EINTR is retried.
func Send(fd uintptr, hdrs []Hdr) (int, syscall.Errno) {
	return call(unix.SYS_SENDMSG_X, fd, hdrs)
}

// Recv passes hdrs to recvmsg_x on fd and returns how many messages it filled. EINTR is retried.
func Recv(fd uintptr, hdrs []Hdr) (int, syscall.Errno) {
	return call(unix.SYS_RECVMSG_X, fd, hdrs)
}

func call(trap, fd uintptr, hdrs []Hdr) (int, syscall.Errno) {
	if len(hdrs) == 0 {
		return 0, syscall.EINVAL
	}
	for {
		r, _, errno := unix.Syscall6(trap, fd, uintptr(unsafe.Pointer(&hdrs[0])), uintptr(len(hdrs)), 0, 0, 0)
		switch errno {
		case 0:
			return int(r), 0
		case syscall.EINTR:
		default:
			return 0, errno
		}
	}
}

// Unsupported reports whether errno means the kernel or a sandbox refuses the private calls.
func Unsupported(errno syscall.Errno) bool {
	return errno == syscall.ENOSYS || errno == syscall.EPERM || errno == syscall.EOPNOTSUPP
}
