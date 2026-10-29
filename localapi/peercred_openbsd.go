//go:build openbsd

package localapi

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCheckSupported reports that this platform can identify a connecting process.
const peerCheckSupported = true

// peerUID returns the uid of the process on the other end of conn.
//
// OpenBSD reports the peer through SO_PEERCRED at SOL_SOCKET, filling a
// `struct sockpeercred { uid_t uid; gid_t gid; pid_t pid; }`. System calls here have to
// go through libc, so the raw getsockopt netbsd uses is not an option, and
// golang.org/x/sys/unix has no typed wrapper for this struct. It does export
// GetsockoptInt, which goes through its libc trampoline with a 4 byte buffer, and the
// kernel copies out min(caller's length, option length): the first four bytes, which are
// the uid. That is a dependence on the field order, the same one netbsd's offset carries.
func peerUID(conn net.Conn) (uid uint32, err error) {
	err = withPeerFD(conn, func(fd int) error {
		v, credErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credErr != nil {
			return credErr
		}
		// A uid_t is 32 bits; GetsockoptInt read exactly that many and widened it.
		uid = uint32(v)
		return nil
	})
	return uid, err
}
