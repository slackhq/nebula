//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package udp

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rawSendmmsg performs sendmmsg(2) over a syscall.RawConn without
// allocating a closure per call. The struct holds preallocated in/out
// scratch (chunk/sent/errno) and a method-value bound at construction so
// rawConn.Write receives a stable function pointer instead of a fresh
// closure on every send.
type rawSendmmsg struct {
	msgs     []rawMessage
	chunk    int
	sent     int
	errno    syscall.Errno
	callback func(fd uintptr) bool
}

// bind wires r.callback to r.run. Must be called once after r.msgs is set;
// subsequent send calls invoke r.callback without rebinding.
func (r *rawSendmmsg) bind() { r.callback = r.run }

// run is the preallocated callback rawConn.Write invokes. It reads its
// input (r.chunk) and writes its outputs (r.sent, r.errno) through the
// rawSendmmsg fields so the method value does not capture per-call locals
// and therefore does not heap-allocate.
func (r *rawSendmmsg) run(fd uintptr) bool {
	r1, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, fd,
		uintptr(unsafe.Pointer(&r.msgs[0])), uintptr(r.chunk),
		0, 0, 0,
	)
	if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
		return false
	}
	r.sent = int(r1)
	r.errno = errno
	return true
}

// send issues sendmmsg over rc against the first n entries of r.msgs.
// Returns the number of entries the kernel processed and any error;
// matches the original sendmmsg helper's contract.
func (r *rawSendmmsg) send(rc syscall.RawConn, n int) (int, error) {
	r.chunk = n
	r.sent = 0
	r.errno = 0
	if err := rc.Write(r.callback); err != nil {
		return r.sent, err
	}
	if r.errno != 0 {
		return r.sent, &net.OpError{Op: "sendmmsg", Err: r.errno}
	}
	return r.sent, nil
}
