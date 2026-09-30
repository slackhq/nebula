//go:build windows

package localapi

import (
	"errors"
	"net"
)

// peerCheckSupported is false where the connecting process is not identified separately.
//
// On windows there is nothing to add: the pipe's security descriptor already admits
// only the account nebula runs as, which is the check, not a second opinion on it.
const peerCheckSupported = false

var errNoPeerCheck = errors.New("peer credentials are not available on this platform")

func peerUID(conn net.Conn) (uint32, error) {
	return 0, errNoPeerCheck
}
