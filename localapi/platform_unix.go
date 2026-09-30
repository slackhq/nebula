//go:build !windows

package localapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
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

// listen binds the socket at path.
//
// Access control is the socket's own mode, 0600, which the node is created with and
// which is pinned after bind, together with the peer check the server applies on accept:
// connect(2) needs write permission on the socket file on every unix we build for. The
// directory is not part of that, and is never chmoded: a directory a service manager
// made for us is served from at whatever mode it came with (systemd's
// RuntimeDirectoryMode= is 0755 by default), and one an operator pointed us into keeps
// whatever else it holds readable. The one we make ourselves is 0755, searchable by
// everyone, so that an unprivileged nebula ctl can see a root daemon's socket and say
// so; see ServedByRootFor.
func listen(path string) (net.Listener, error) {
	// The kernel silently truncates an over long sun_path and bind then fails with
	// "invalid argument", which tells an operator nothing. Say what is actually wrong.
	if pathTooLong(path) {
		return nil, fmt.Errorf("socket path is %d bytes, over the %d byte limit for a unix socket: %s", len(path), maxSocketPath, path)
	}

	dir := filepath.Dir(path)

	// One level only. Every directory defaultPathFor offers sits directly under one that
	// exists, and an operator who names a deeper path creates it; a missing parent is a
	// mistake to report, not a tree to build. A directory made here is remembered, so
	// that removeSocket can take it away again once nothing is left in it.
	//
	// 0755 gives nothing away: the socket is 0600. What it gives is a directory others
	// can look into, which is what ServedByRootFor needs. Mkdir applies the umask, so
	// the mode is pinned afterwards, as the socket's is; only on a directory this call
	// created.
	switch err := os.Mkdir(dir, 0755); {
	case err == nil:
		if err := os.Chmod(dir, 0755); err != nil {
			return nil, fmt.Errorf("could not set the mode of %s: %w", dir, err)
		}
		madeDirs.add(dir)
	case !errors.Is(err, os.ErrExist):
		return nil, fmt.Errorf("could not create %s: %w", dir, err)
	}

	if err := clearStale(path); err != nil {
		return nil, err
	}

	// bind creates the socket node at the process umask, and a connect(2) between that
	// and a later chmod would be queued for accept. Tighten the umask around the bind so
	// the node is never looser than 0600, however briefly. umask is process wide, so
	// another goroutine creating a file during this one syscall gets 0600 too: stricter
	// than it asked for, never looser, and nothing here creates files on a hot path.
	old := syscall.Umask(0077)
	ln, err := net.Listen(network, path)
	syscall.Umask(old)
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

	// The umask only promises no looser than 0600; this pins the mode exactly, and is
	// the one place a failure to secure the socket is reported.
	if err := os.Chmod(path, 0600); err != nil {
		release(ln, path)
		return nil, fmt.Errorf("could not secure %s: %w", path, err)
	}

	return ln, nil
}

// owner returns the uid that owns the file fi describes.
func owner(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint32(st.Uid), true
}

// checkSocket refuses to dial a socket that is not ours. A path, derived or named, says
// where our daemon should be; the socket's owner says whether that is what is there,
// since nobody can create a socket owned by somebody else. The daemon's own mode and
// peer check would turn a stranger away regardless; this is so the refusal says whose
// socket it is and what to do about it, instead of a bare permission denied, and so the
// request, which carries the command and its arguments, is never sent to a socket that
// is not our daemon's.
//
// Root is no exception. A root nebula ctl has business with a root daemon, whose socket
// is root's; a daemon run by a service account is reached by running nebula ctl as that
// account, which derives the same path it did.
func checkSocket(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}

	if !isSocket(fi) {
		return fmt.Errorf("%s is not a socket", path)
	}

	if uid, ok := owner(fi); ok && uid != currentUID() {
		return fmt.Errorf("%s is owned by %s, not by you; run nebula ctl as that user", path, describeUID(uid))
	}

	return nil
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
	madeDirs.remove(filepath.Dir(path))
}

// madeDirs is the set of directories listen created and has not yet removed. It is
// package state because the socket's path is all release and listen share.
var madeDirs = dirSet{made: map[string]bool{}}

type dirSet struct {
	mu   sync.Mutex
	made map[string]bool
}

func (d *dirSet) add(dir string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.made[dir] = true
}

// remove takes dir away if listen made it and it is empty. One that still holds
// something, another socket of ours or whatever else arrived, is kept and stays
// remembered, so the release of the last socket in it is the one that removes it. The
// same goes for any other failure: a directory that is still there is still ours to
// remove, and the next release tries again. Only one that is gone is forgotten.
func (d *dirSet) remove(dir string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.made[dir] {
		return
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
	delete(d.made, dir)
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

func pathTooLong(path string) bool { return len(path) > maxSocketPath }

// resolveOverride turns a CtlSocketKey value into the one absolute path both the daemon
// and the CLI will use. A relative value is taken from the config's directory, see
// configDir; an absolute one is only cleaned. Abs fails only when the working directory
// cannot be read, and then the joined path is as good an answer as there is.
func resolveOverride(override, configPath string) string {
	p := override
	if !filepath.IsAbs(p) {
		p = filepath.Join(configDir(configPath), p)
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return p
}

// logListening is the line written when the socket is up. Every unix this builds for
// checks the peer's credentials on each connection, on top of the socket's mode, so the
// line has only the path to add.
func logListening(l *slog.Logger, path string) {
	l.Info("Local control socket listening", "path", path)
}

// systemDir is where a daemon run by root, or handed a runtime directory by a service
// manager, keeps its socket.
var systemDir = filepath.Join("/var/run", DirName)

// defaultPathFor picks the directory the socket lives in, the same way on both sides.
//
// Root serves from /var/run/nebula and nowhere else: it needs no environment, which is
// all a service manager gives a daemon. XDG_RUNTIME_DIR is ignored for root on purpose:
// under sudo it is often the invoking user's, and a root daemon and a root CLI have to
// agree without either knowing how the other was started.
//
// Anyone else serves from /var/run/nebula when a service manager handed it to them
// (systemd's RuntimeDirectory= together with User=), else from their login session's
// runtime dir, else from a private temp dir. No candidate may sit under a directory
// other users can write to, see openToOthers. On linux an unset TMPDIR means /tmp, which
// fails that rule, so a daemon with no session and no RuntimeDirectory gets no socket
// and a log line saying which to add. That is the intended outcome: the one place such a
// daemon could otherwise have fallen back to is the one place any user can lay out a
// socket directory in advance.
func defaultPathFor(shortHash string) (string, error) {
	name := shortHash + SocketExt

	var reasons []string
	for _, dir := range candidateDirs() {
		p := filepath.Join(dir, name)
		if pathTooLong(p) {
			reasons = append(reasons, fmt.Sprintf("%s: path would be %d bytes, over the %d byte limit", dir, len(p), maxSocketPath))
			continue
		}

		if err := openToOthers(filepath.Dir(dir)); err != nil {
			reasons = append(reasons, err.Error())
			continue
		}

		return p, nil
	}

	return "", fmt.Errorf("no usable directory for the control socket (%s); run nebula with a private runtime directory, such as RuntimeDirectory=nebula under systemd, or set %s",
		strings.Join(reasons, "; "), CtlSocketKey)
}

// openToOthers refuses a directory other users can write to, /tmp above all. A derived
// socket directory is never placed under one: the daemon and the CLI compute the path
// without looking, so anyone could create the directory there first and hold the path
// both of them will use. The check is on the parent, not on a directory of our own: the
// socket's mode is what keeps others out of it. It is a rule for derived paths only; a
// path the operator named is used as given.
func openToOthers(parent string) error {
	fi, err := os.Stat(parent)
	if err != nil {
		return err
	}

	if fi.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("%s is writable by other users (mode %04o), refusing to derive a socket path under it", parent, fi.Mode().Perm())
	}

	return nil
}

// candidateDirs lists socket directories in preference order.
func candidateDirs() []string {
	me := currentUID()
	if me == 0 {
		return []string{systemDir}
	}

	var dirs []string

	// A service manager's runtime directory is handed over ready made, so it counts only
	// when it is already there and already ours. Nobody but root can create it.
	if fi, err := os.Stat(systemDir); err == nil {
		if uid, ok := owner(fi); ok && uid == me {
			dirs = append(dirs, systemDir)
		}
	}

	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		dirs = append(dirs, filepath.Join(rt, DirName))
	}

	return append(dirs, filepath.Join(os.TempDir(), DirName))
}

// ServedByRootFor reports the socket a root daemon would be serving for configPath,
// when the caller is not root and that socket exists. It answers the common first try,
// `nebula ctl` from a user's shell against a `sudo nebula`: the two derive different
// directories, so the user's path is empty, or cannot be derived at all in a shell with
// no runtime directory and only /tmp to offer, while root's is there. The name is the
// hash of the config, so a match means the same config and not some other daemon's
// socket.
//
// A path chosen by local_api.control.socket is not hashed and so never matches, which is
// right: both sides read that key, and a daemon with it set serves where it says.
//
// The probe is a stat, which needs search permission on systemDir. listen creates it
// 0755 for exactly this; a directory a service manager made is whatever mode it gave
// it, and one that is 0700 answers "no" here even when a root daemon is serving.
func ServedByRootFor(configPath string) (string, bool) {
	return servedByRoot(shortHash(configPath) + SocketExt)
}

func servedByRoot(name string) (string, bool) {
	if currentUID() == 0 {
		return "", false
	}

	p := filepath.Join(systemDir, name)
	fi, err := os.Stat(p)
	if err != nil || !isSocket(fi) {
		return "", false
	}

	return p, true
}

func isSocket(fi os.FileInfo) bool { return fi.Mode()&os.ModeSocket != 0 }
