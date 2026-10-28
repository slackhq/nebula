//go:build illumos || solaris

package localapi

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCheckSupported reports that this platform can identify a connecting process.
const peerCheckSupported = true

// peerUID returns the effective uid of the process on the other end of conn, read
// with getpeerucred(3C).
func peerUID(conn net.Conn) (uid uint32, err error) {
	err = withPeerFD(conn, func(fd int) error {
		uc, credErr := unix.GetPeerUcred(uintptr(fd))
		if credErr != nil {
			return credErr
		}
		uid = uint32(uc.Geteuid())
		return nil
	})
	return uid, err
}
