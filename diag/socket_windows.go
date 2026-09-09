//go:build windows

package diag

import (
	"net"
	"time"
)

// Windows has AF_UNIX since Windows 10 1803, but no way to secure the socket that resembles
// what the unix build does: os.Chmod cannot express an ACL, and a socket's reachability comes
// down to whatever its directory inherited. Doing this properly means a named pipe with an
// explicit security descriptor, which is a dependency and a design this change does not carry.
// Until then the stub keeps the package building and gives operators a real answer.

// DefaultSocketPath returns an empty string: there is no path worth defaulting to here.
func DefaultSocketPath() string {
	return ""
}

func listenSocket(path string) (net.Listener, error) {
	return nil, ErrNotSupported
}

func dialSocket(path string, timeout time.Duration) (net.Conn, error) {
	return nil, ErrNotSupported
}
