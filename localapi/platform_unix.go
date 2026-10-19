//go:build !windows

package localapi

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const network = "unix"

// withPeerFD runs f on the descriptor behind conn, which must be a unix socket, and
// returns whichever error came first: not a unix socket, no raw access to it, or f's
// own. It is the scaffolding every platform's peerUID shares; only the getsockopt inside
// differs.
func withPeerFD(conn net.Conn, f func(fd int) error) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}

	var inner error
	if err := raw.Control(func(fd uintptr) { inner = f(int(fd)) }); err != nil {
		return err
	}
	return inner
}

// currentUID is the user the owner checks are made for. A variable so a test can stand
// in for root, or for a stranger, without owning a second account on the host.
var currentUID = func() uint32 { return uint32(os.Geteuid()) }

// listen binds the socket at path with the given access.
//
// Access control is the socket's own mode and group, which the node is created no
// looser than and which are set after bind, together with the peer check the server
// applies on accept unless a group shares the socket, in which case the kernel's check
// is the whole of it: connect(2) needs write permission on the socket file on every
// unix we build for.
//
// The directory is not part of that, and is never chmoded: a directory a service
// manager made for us is served from at whatever mode it came with (systemd's
// RuntimeDirectoryMode= is 0755 by default), and one an operator pointed us into keeps
// whatever else it holds readable. The one we make ourselves is 0755, searchable by
// everyone, so that a nebula ctl run as another user reaches the socket and gets the
// kernel's answer, which for a member of the configured group is a connection and for
// anyone else is permission denied.
func listen(path string, acc Access) (net.Listener, error) {
	// The kernel silently truncates an over long sun_path and bind then fails with
	// "invalid argument", which tells an operator nothing. Say what is actually wrong.
	if pathTooLong(path) {
		return nil, fmt.Errorf("socket path is %d bytes, over the %d byte limit for a unix socket: %s", len(path), maxSocketPath, path)
	}

	dir := filepath.Dir(path)

	// One level only. Every directory defaultPathFor offers sits directly under one that
	// exists, and an operator who names a deeper path creates it; a missing parent is a
	// mistake to report, not a tree to build. A directory made here stays when the
	// socket goes: an empty one costs nothing, and the next start wants it again.
	//
	// The mode comes from the umask around the call, never from a chmod afterwards: a
	// chmod by path could land on whatever somebody who can write the parent swapped in
	// between the two calls, and a chmod through a descriptor on a root-owned directory
	// they moved there, since root owns both. Born 0755 there is nothing to fix up.
	// The umask is process wide and the window is one syscall; see umaskMu.
	umaskMu.Lock()
	old := syscall.Umask(0022)
	err := os.Mkdir(dir, 0755)
	syscall.Umask(old)
	umaskMu.Unlock()
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("could not create %s: %w", dir, err)
	}

	// Whether it was made here or came with the environment, the directory has to be
	// one nobody else could change; see checkSocketDir.
	if err := checkSocketDir(dir); err != nil {
		return nil, err
	}

	if err := clearStale(path); err != nil {
		return nil, err
	}

	// bind creates the socket node at the process umask, and a connect(2) between that
	// and a later chmod would be queued for accept. Tighten the umask around the bind so
	// the node is never looser than 0600, however briefly; see umaskMu.
	umaskMu.Lock()
	old = syscall.Umask(0077)
	ln, err := net.Listen(network, path)
	syscall.Umask(old)
	umaskMu.Unlock()
	if err != nil {
		return nil, err
	}

	// The node at path is given up by release, which unlinks it before the listener
	// closes; see there for why the order matters. Go's listener would unlink on Close
	// as well, and an unlink after the close could only be of whatever bound the path
	// next, so that is turned off and release is the one place the node is removed.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}

	// The umask only promises no looser than 0600; this pins the mode and the group
	// exactly, and is the one place a failure to secure the socket is reported.
	if err := applyAccess(path, acc); err != nil {
		release(ln, path)
		return nil, fmt.Errorf("could not secure %s: %w", path, err)
	}

	return ln, nil
}

// applyAccess sets the owning group and the mode of the socket node at path. With no
// group configured the socket is handed back to the daemon's own group, so taking the
// key out of the config on a reload takes the access away as surely as a restart would.
// The chown is Lchown, so a link at the path is not followed to its target.
func applyAccess(path string, acc Access) error {
	gid, err := gidFor(acc)
	if err != nil {
		return err
	}
	if err := os.Lchown(path, -1, gid); err != nil {
		return err
	}
	return os.Chmod(path, acc.Mode.Perm())
}

// checkSocketDir refuses to serve from a directory that somebody other than the user
// nebula runs as, or root, could change. The socket's mode and group say who may connect
// to it; what makes the path they connect to the daemon's is the directory, since
// whoever can write it can put a socket of their own at the path and answer the clients
// in the daemon's place. So the directory must be owned by the daemon's user or by root
// and writable by its owner alone; a sticky bit is not an exception. A runtime directory
// a service manager made for another user, or /var/run/nebula created ahead of a root
// daemon by a member of group daemon, where darwin lets that group write /var/run, are
// both refused with the owner named.
//
// A link where the directory should be is judged twice: whoever owns the link decides
// where the path leads, so the link must be ours or root's too, and the directory it
// resolves to is then held to the rule above. /var/run is such a link on linux, root's,
// to /run, and a socket named directly under it is served; a link somebody else planted
// is refused as theirs.
//
// Only this directory is checked, not the ones above it. /var/run itself is group
// writable on darwin by design, and the parents are the operator's to trust, as they are
// for every file nebula reads. The check is made at bind, so a directory loosened while
// the daemon runs is noticed at the next reload.
func checkSocketDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		if uid, ok := owner(fi); ok && uid != currentUID() && uid != 0 {
			return fmt.Errorf("%s is a symlink owned by %s, not by the user nebula runs as or by root, and its owner decides where the path leads; name a socket path that does not go through it", dir, describeUID(uid))
		}
		if fi, err = os.Stat(dir); err != nil {
			return err
		}
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	if uid, ok := owner(fi); ok && uid != currentUID() && uid != 0 {
		return fmt.Errorf("%s is owned by %s, not by the user nebula runs as or by root, and its owner could replace the socket; make it ours or root's, or name a socket path in a directory that is", dir, describeUID(uid))
	}

	if perm := fi.Mode().Perm(); perm&0022 != 0 {
		who := "its group"
		if perm&0002 != 0 {
			who = "everyone"
		}
		return fmt.Errorf("%s is writable by %s (mode %04o), who could replace the socket; make it writable by its owner alone, or name a socket path in a directory that is", dir, who, perm)
	}

	return nil
}

// owner returns the uid that owns the file fi describes.
func owner(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(st.Uid), true
}

// describeUID renders a uid with its account name when the host can say what it is, so
// a message about somebody else's socket tells the operator who that is.
func describeUID(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil && u.Username != "" {
		return "uid " + id + " (" + u.Username + ")"
	}

	return "uid " + id
}

// clearStale removes a leftover socket file, but only after proving nothing is
// listening on it. An unclean restart leaves one behind every time, so this is a
// routine path; blindly unlinking would let a second daemon steal a live endpoint.
//
// Liveness is a plain connect. Only a refused connect proves there is nothing behind
// the file. Anything else, a timeout or a permission error, is a socket we cannot vouch
// for, and it is left alone with the reason in the error.
func clearStale(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if !isSocket(fi) {
		return fmt.Errorf("%s exists and is not a socket", path)
	}

	conn, err := dial(path, 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("%s is already in use by another nebula instance", path)
	}

	if errors.Is(err, os.ErrNotExist) {
		// Gone between the stat and the connect; nothing to clear.
		return nil
	}

	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%s exists and could not be shown to be stale, refusing to remove it: %w", path, err)
	}

	return os.Remove(path)
}

// removeSocket unlinks the socket node and, when listen made the directory it is in,
// removes that too, so a socket that moves off an override or a daemon that stops
// leaves nothing behind. A directory that came with the environment, a service
// manager's runtime directory or one the operator pointed us into, is not ours to
// remove and is left as it was.
func removeSocket(path string) {
	_ = os.Remove(path)
}

func dial(path string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, path, timeout)
}

// sunPathMax is the smallest sun_path any platform we build for offers (104 on darwin,
// 108 on linux). Overrunning it truncates the path rather than failing cleanly, so we
// check against the tighter bound everywhere.
const sunPathMax = 104

// maxSocketPath is the longest path that actually binds. sun_path holds the trailing
// NUL as well, and Go's syscall package refuses a path that fills the whole buffer
// with a bare EINVAL, so the usable limit is one byte short of the buffer.
const maxSocketPath = sunPathMax - 1

// umaskMu serialises the two places the process umask is set around one syscall: the
// umask is process wide, and two endpoints binding at once, a reload landing during
// startup, would otherwise interleave their save and restore and leave the daemon's
// umask at one of ours. It is held for the syscall alone. Another goroutine creating a
// file in that moment gets the umask of the window, 0022 or 0077, rather than the
// process's own; nothing creates files on a hot path.
var umaskMu sync.Mutex

func pathTooLong(path string) bool { return len(path) > maxSocketPath }

// DefaultSocketPath is the control socket when the config names none. It is root's to
// create, as the tun device is root's to open; a daemon run as anyone else names a path
// of its own with CtlSocketKey.
const DefaultSocketPath = "/var/run/" + DirName + "/ctl.sock"

// checkSocketPath refuses a configured socket path that is relative, or too long to
// bind. A relative path would mean a different socket to the daemon and to nebula ctl,
// each resolving it against the directory it happened to be started from.
func checkSocketPath(key, value string) error {
	if !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be an absolute path, got %q", key, value)
	}
	if pathTooLong(value) {
		return fmt.Errorf("%s is %d bytes, too long for this platform: %s", key, len(value), value)
	}
	return nil
}

func isSocket(fi os.FileInfo) bool { return fi.Mode()&os.ModeSocket != 0 }
