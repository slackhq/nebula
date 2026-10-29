//go:build netbsd

package localapi

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const peerCheckSupported = true

// NetBSD reports the peer's identity through LOCAL_PEEREID at the SOL_LOCAL level,
// filling a `struct unpcbid { pid_t unp_pid; uid_t unp_euid; gid_t unp_egid; }`.
// golang.org/x/sys/unix has no typed wrapper for it, so the getsockopt goes out by hand
// exactly the way that package's own generated wrappers do on this platform.
const (
	solLocal     = 0
	localPeerEID = 0x0003

	unpcbidSize     = 12
	unpcbidEUIDOffs = 4
)

// peerUID returns the uid of the process on the other end of conn.
//
// Anything unexpected here is an error rather than a default, so a wrong constant or an
// unsupported kernel refuses connections instead of silently admitting them.
func peerUID(conn net.Conn) (uid uint32, err error) {
	err = withPeerFD(conn, func(fd int) error {
		var (
			buf  [unpcbidSize]byte
			size = uint32(unpcbidSize)
		)

		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			uintptr(fd),
			uintptr(solLocal),
			uintptr(localPeerEID),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			return errno
		}

		if size != unpcbidSize {
			return fmt.Errorf("LOCAL_PEEREID returned %d bytes, expected %d", size, unpcbidSize)
		}

		// Read, not cast: the buffer is bytes, and a cast would fault on an
		// architecture that wants the uint32 aligned.
		uid = binary.NativeEndian.Uint32(buf[unpcbidEUIDOffs:])
		return nil
	})
	return uid, err
}
