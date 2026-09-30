//go:build darwin || freebsd

package localapi

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCheckSupported reports that this platform can identify a connecting process.
const peerCheckSupported = true

// peerUID returns the uid of the process on the other end of conn.
func peerUID(conn net.Conn) (uid uint32, err error) {
	err = withPeerFD(conn, func(fd int) error {
		xu, credErr := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr != nil {
			return credErr
		}
		uid = xu.Uid
		return nil
	})
	return uid, err
}
