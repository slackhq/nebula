//go:build linux

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
		cred, credErr := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credErr != nil {
			return credErr
		}
		uid = cred.Uid
		return nil
	})
	return uid, err
}
