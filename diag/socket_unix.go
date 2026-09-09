//go:build !windows

package diag

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// maxSocketPath is the smallest sun_path across the platforms nebula ships on: 104 bytes on
// darwin and the BSDs, 108 on Linux. Checking it ourselves turns a bare "invalid argument"
// into something an operator can act on.
const maxSocketPath = 103

// DefaultSocketPath is where nebula listens when ctl.socket is unset. An empty string means
// the platform has no sensible default and ctl stays off unless an operator names a path.
func DefaultSocketPath() string {
	switch runtime.GOOS {
	case "ios", "android":
		// No daemon to attach to and no shell to attach from, and nowhere writable that
		// would survive being guessed. Mobile embedders drive nebula through Control.
		return ""
	case "linux":
		return "/run/nebula/ctl.sock"
	default:
		// /run does not exist on darwin, and /var/run is the portable spelling everywhere
		// else nebula builds.
		return "/var/run/nebula/ctl.sock"
	}
}

// listenSocket creates the listening socket at path, taking over one a previous nebula left
// behind but refusing one that is still being served.
func listenSocket(path string) (net.Listener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("socket path is %d bytes, the maximum is %d", len(path), maxSocketPath)
	}

	// The directory, not the socket, is what enforces access control. net.Listen creates the
	// socket with 0777&^umask, so with a typical 0022 umask it is world connectable for the
	// window between bind and chmod. Nobody can traverse into a 0700 directory to reach it in
	// that window, and unlike the socket's own mode, directory traversal is enforced
	// consistently across every platform this file builds for.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to set permissions on %s: %w", dir, err)
	}

	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}

	// Defence in depth behind the directory, for anyone who relocates the socket somewhere
	// more permissive.
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}

	return ln, nil
}

// dialSocket connects to a nebula serving at path.
func dialSocket(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", path, timeout)
}

// clearStaleSocket removes a socket a crashed nebula left behind, but refuses to steal one
// another nebula is still serving. Two instances on one host need two paths; they cannot
// share one, and silently taking the socket would break the instance that got there first.
func clearStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket, refusing to remove it", path)
	}

	// A successful dial is the only reliable way to tell a live socket from an abandoned
	// one; the inode looks identical either way.
	c, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("%s is already being served, is another nebula running?", path)
	}

	return os.Remove(path)
}
