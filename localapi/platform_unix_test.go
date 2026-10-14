//go:build !windows

package localapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// privateBase returns a short directory of our own, 0700, for tests to lay sockets out
// under. It also becomes TMPDIR for the test, so a derived path lands under it as well,
// and stays short enough for sun_path.
func privateBase(t *testing.T) string {
	t.Helper()

	base := test.ShortTempDir(t)
	t.Setenv("TMPDIR", base)

	return base
}

// openDir returns a world writable directory under base, the shape of /tmp.
func openDir(t *testing.T, base string) string {
	t.Helper()

	open := filepath.Join(base, "open")
	require.NoError(t, os.Mkdir(open, 0777))
	require.NoError(t, os.Chmod(open, 0777|os.ModeSticky))
	return open
}

// TestListenLeavesAServiceManagersDirectoryAlone covers the directory a service manager
// pre-creates: systemd's RuntimeDirectory is 0755 by default. The socket is 0600, which
// is what refuses other users, so the directory is served from as it came and nothing
// is chmoded that the operator did not set.
func TestListenLeavesAServiceManagersDirectoryAlone(t *testing.T) {
	base := privateBase(t)
	dir := filepath.Join(base, DirName)
	require.NoError(t, os.Mkdir(dir, 0755))

	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(context.Background(), filepath.Join(dir, "s.sock")))
	t.Cleanup(s.Stop)

	fi, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), fi.Mode().Perm(), "the directory is left exactly as it was")

	fi, err = os.Stat(s.Path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(), "the socket is what is private")
	_, err = (&Client{Path: s.Path()}).Describe()
	require.NoError(t, err)
}

// TestListenCreatesOneLevelOnly: the socket directory is created when it is missing,
// but nothing above it is. A runtime directory that does not exist is the operator's to
// provide, and the failure says which directory could not be created.
func TestListenCreatesOneLevelOnly(t *testing.T) {
	base := privateBase(t)

	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(context.Background(), filepath.Join(base, DirName, "s.sock")))
	s.Stop()

	dir := filepath.Join(base, "missing", DirName)
	err := s.Rebind(context.Background(), filepath.Join(dir, "s.sock"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "could not create "+dir)
	assert.NoDirExists(t, filepath.Join(base, "missing"))
}

// TestReleaseRemovesTheDirectoryItMade: a directory listen created goes away with the
// last socket in it, and one that was already there is left alone, whatever it holds.
func TestReleaseRemovesTheDirectoryItMade(t *testing.T) {
	base := privateBase(t)

	made := filepath.Join(base, DirName)
	first, err := listen(filepath.Join(made, "a.sock"), ctlSocketMode)
	require.NoError(t, err)
	second, err := listen(filepath.Join(made, "b.sock"), ctlSocketMode)
	require.NoError(t, err)

	release(first, filepath.Join(made, "a.sock"))
	assert.DirExists(t, made, "b.sock is still in it")
	release(second, filepath.Join(made, "b.sock"))
	assert.NoDirExists(t, made)

	given := filepath.Join(base, "given")
	require.NoError(t, os.Mkdir(given, 0755))
	ln, err := listen(filepath.Join(given, "s.sock"), ctlSocketMode)
	require.NoError(t, err)
	release(ln, filepath.Join(given, "s.sock"))
	assert.DirExists(t, given)
	assert.NoFileExists(t, filepath.Join(given, "s.sock"))
}

// TestListenRestoresTheUmask: listen tightens the process umask around bind so the socket
// node is never created looser than 0600. That is process wide state, so it must come
// back exactly as it was, on success and on failure alike.
func TestListenRestoresTheUmask(t *testing.T) {
	old := syscall.Umask(0022)
	t.Cleanup(func() { syscall.Umask(old) })

	base := privateBase(t)
	ln, err := listen(filepath.Join(base, DirName, "s.sock"), ctlSocketMode)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	assert.Equal(t, 0022, syscall.Umask(0022), "umask after a successful listen")

	_, err = listen(filepath.Join(base, DirName, "s.sock"), ctlSocketMode)
	require.Error(t, err, "the path is already bound")
	assert.Equal(t, 0022, syscall.Umask(0022), "umask after a failed listen")
}

// TestListenServesFromASharedDirectory: an operator who points local_api.control.socket
// into a directory holding other files, /etc/nebula say, gets a socket there and keeps
// the config and certs readable by everyone who could read them before.
func TestListenServesFromASharedDirectory(t *testing.T) {
	base := privateBase(t)
	dir := filepath.Join(base, "etc-nebula")
	require.NoError(t, os.Mkdir(dir, 0755))
	cfg := filepath.Join(dir, "config.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("{}\n"), 0644))

	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(context.Background(), filepath.Join(dir, "ctl.sock")))
	t.Cleanup(s.Stop)

	fi, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), fi.Mode().Perm())
	fi, err = os.Stat(cfg)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), fi.Mode().Perm())
}

func TestOverlongPathIsDiagnosed(t *testing.T) {
	long := filepath.Join(os.TempDir(), string(make([]byte, 0)))
	for len(long) <= sunPathMax {
		long = filepath.Join(long, "abcdefghij")
	}

	s := NewServer(test.NewLogger(), basicRegistry())
	err := s.Rebind(context.Background(), filepath.Join(long, "s.sock"))

	require.Error(t, err)
	assert.ErrorContains(t, err, "byte limit for a unix socket")
}

// TestPathLimitIsExact pins the boundary: sun_path has room for the NUL as well, and Go
// refuses a path that fills the whole buffer, so the last usable length is one short.
func TestPathLimitIsExact(t *testing.T) {
	assert.False(t, pathTooLong(strings.Repeat("a", maxSocketPath)))
	assert.True(t, pathTooLong(strings.Repeat("a", maxSocketPath+1)))
	assert.True(t, pathTooLong(strings.Repeat("a", sunPathMax)))
}

// TestDefaultPathUsesTheRuntimeDirectory: the login session's runtime directory is the
// derived home for a user's socket, whether the socket directory under it already
// exists, at whatever mode, or is yet to be created by listen. The socket's own mode is
// what keeps others out, so an open directory of ours is still ours.
func TestDefaultPathUsesTheRuntimeDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root's only candidate is /var/run/nebula, which this test should not touch")
	}

	base := privateBase(t)
	runtimeDir := filepath.Join(base, "rt")
	require.NoError(t, os.MkdirAll(filepath.Join(runtimeDir, DirName), 0755))
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	cfg := filepath.Join(base, "config.yml")

	p, err := DefaultSocketPath(cfg)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(runtimeDir, DirName), filepath.Dir(p), "ours and open is still ours")

	require.NoError(t, os.RemoveAll(filepath.Join(runtimeDir, DirName)))
	p, err = DefaultSocketPath(cfg)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(runtimeDir, DirName), filepath.Dir(p), "absent is fine")
}

// TestDefaultPathRefusesToLandUnderTmp: with no session and no runtime directory the
// answer is no socket and a message naming the fix, never a socket under /tmp.
func TestDefaultPathRefusesToLandUnderTmp(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root's only candidate is /var/run/nebula, which this test should not touch")
	}

	base := test.ShortTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", openDir(t, base))

	_, err := DefaultSocketPath(filepath.Join(base, "config.yml"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "writable by other users")
	assert.ErrorContains(t, err, "RuntimeDirectory=nebula")
	assert.ErrorContains(t, err, CtlSocketKey)
}

// TestNamedPathIsUsedAsGiven: the rule against world writable directories is for
// derived paths, which nobody looked at. A path the operator named is served from, and
// dialed, wherever it is.
func TestNamedPathIsUsedAsGiven(t *testing.T) {
	base := privateBase(t)
	path := filepath.Join(openDir(t, base), DirName, "s.sock")

	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(context.Background(), path))
	t.Cleanup(s.Stop)

	_, err := (&Client{Path: path}).Describe()
	require.NoError(t, err)
}

// TestStaleSocketIsCleared: a dead socket in a good directory is the routine leftover of
// a hard kill, and the daemon's stale check must see it as free to replace.
func TestStaleSocketIsCleared(t *testing.T) {
	path := testSocket(t)
	require.NoError(t, os.Mkdir(filepath.Dir(path), 0700))
	ln, err := net.Listen(network, path)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(path, 0600))
	// Close the listener but keep the file, the way a hard kill does.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, ln.Close())
	_, statErr := os.Stat(path)
	require.NoError(t, statErr, "the socket file is still there")

	require.NoError(t, clearStale(path), "a stale socket is cleared, not reported as in use")
	_, statErr = os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

// TestClientGivesUpOnASilentDaemon: a daemon that accepts and then never answers must
// not hang the client for good. A script wrapping nebula ctl has no other way out.
func TestClientGivesUpOnASilentDaemon(t *testing.T) {
	path := testSocket(t)
	require.NoError(t, os.Mkdir(filepath.Dir(path), 0700))
	ln, err := net.Listen(network, path)
	require.NoError(t, err)
	defer ln.Close()
	require.NoError(t, os.Chmod(path, 0600))

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c // held open, never written to
		}
	}()

	start := time.Now()
	_, err = (&Client{Path: path, Timeout: 200 * time.Millisecond}).Describe()
	require.Error(t, err)
	assert.ErrorContains(t, err, "did not answer within")
	assert.Less(t, time.Since(start), 5*time.Second)

	select {
	case c := <-accepted:
		_ = c.Close()
	default:
	}
}

// asUID makes the owner checks run as uid for the rest of the test. The socket the test
// serves is still owned by the real user, so from uid's point of view it belongs to
// somebody else: the shape of a service account's daemon, and of an impostor's.
func asUID(t *testing.T, uid uint32) {
	t.Helper()
	real := currentUID
	currentUID = func() uint32 { return uid }
	t.Cleanup(func() { currentUID = real })
}

// TestServedByRootForAConfig: the probe is made from the config, which is what the
// daemon hashed, and finds root's socket by that name and nothing else: not for root,
// who already looked there, not when nothing is bound, and not for a plain file.
func TestServedByRootForAConfig(t *testing.T) {
	base := privateBase(t)
	sys := filepath.Join(base, DirName)
	require.NoError(t, os.Mkdir(sys, 0755))
	realSys := systemDir
	systemDir = sys
	t.Cleanup(func() { systemDir = realSys })

	cfg := filepath.Join(base, "config.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("{}\n"), 0600))

	asUID(t, 1000)
	_, ok := ServedByRootFor(cfg)
	assert.False(t, ok, "nothing is bound there yet")

	ln, err := net.Listen("unix", filepath.Join(sys, shortHash(cfg)+SocketExt))
	require.NoError(t, err)
	defer ln.Close()

	got, ok := ServedByRootFor(cfg)
	assert.True(t, ok)
	assert.Equal(t, filepath.Join(sys, shortHash(cfg)+SocketExt), got)

	_, ok = ServedByRootFor(filepath.Join(base, "other.yml"))
	assert.False(t, ok, "a different config hashes to a different name")

	plain := filepath.Join(base, "plain.yml")
	require.NoError(t, os.WriteFile(filepath.Join(sys, shortHash(plain)+SocketExt), nil, 0600))
	_, ok = ServedByRootFor(plain)
	assert.False(t, ok, "a regular file is not a socket")

	asUID(t, 0)
	_, ok = ServedByRootFor(cfg)
	assert.False(t, ok, "root derives the system path itself")
}

// TestPeerCheckIsMadeForTheSameIdentityAsTheOwnerCheck: the uid a connection is checked
// against is the one the client's owner check is made for, taken from the same seam. A
// server built as one user and serving as another refuses the real user at the peer
// check, which is only observable if the two identities come from one place.
func TestPeerCheckIsMadeForTheSameIdentityAsTheOwnerCheck(t *testing.T) {
	if !peerCheckSupported {
		t.Skip("no peer credentials on this platform")
	}

	me := currentUID()
	asUID(t, me+1)
	s := NewServer(test.NewLogger(), basicRegistry())
	asUID(t, me)

	path := testSocket(t)
	require.NoError(t, s.Rebind(context.Background(), path))
	defer s.Stop()

	_, err := (&Client{Path: path}).Describe()
	require.Error(t, err)
	assert.ErrorContains(t, err, "not permitted")
}

// TestAnotherUsersSocketIsRefused: a socket owned by somebody else is not our daemon's,
// so nothing is sent to it, and the refusal says whose it is and what to do about it.
// The socket mode and the peer check would stop a stranger anyway; root they would
// admit, and root is refused here all the same, since a root daemon's socket is root's
// and any other is reached by running nebula ctl as its owner.
func TestAnotherUsersSocketIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the socket is owned by root here, so root is not another user")
	}

	path := testSocket(t)
	_, stop := serveAt(t, path)
	defer stop()
	_, err := (&Client{Path: path}).Describe()
	require.NoError(t, err, "the socket is ours before the test pretends otherwise")

	owner := currentUID()
	for _, uid := range []uint32{owner + 1, 0} {
		asUID(t, uid)

		_, err := (&Client{Path: path}).Describe()
		require.Error(t, err, "uid %d", uid)
		assert.ErrorContains(t, err, "not by you")
		assert.ErrorContains(t, err, "uid "+strconv.Itoa(int(owner)))
		assert.ErrorContains(t, err, "as that user")
	}
}

// TestListenerDoesNotUnlinkOnClose: the server unlinks its socket node itself, before
// the listener closes, and the listener must not unlink again afterwards. By the time a
// close happens the path may belong to a newer daemon that found the node stale and
// bound its own, and a second unlink would take that daemon's socket from under it.
func TestListenerDoesNotUnlinkOnClose(t *testing.T) {
	path := filepath.Join(privateBase(t), DirName, "s.sock")
	old, err := listen(path, ctlSocketMode)
	require.NoError(t, err)

	// A newer daemon's start, with the old node gone and the path bound afresh.
	require.NoError(t, os.Remove(path))
	next, err := net.Listen(network, path)
	require.NoError(t, err)
	t.Cleanup(func() { next.Close() })

	require.NoError(t, old.Close())
	_, err = os.Stat(path)
	assert.NoError(t, err, "closing the old listener left the newer daemon's socket in place")
}

// TestMadeDirStaysRememberedUntilItIsGone: a directory listen created that cannot be
// removed right now is still ours to remove, so the record survives the failure and the
// next release tries again. Only a directory that is gone is forgotten.
func TestMadeDirStaysRememberedUntilItIsGone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not refused by directory permissions")
	}

	parent := t.TempDir()
	dir := filepath.Join(parent, "nebula")
	require.NoError(t, os.Mkdir(dir, 0o755))

	d := dirSet{made: map[string]bool{}}
	d.add(dir)

	// A parent without write permission refuses the rmdir.
	require.NoError(t, os.Chmod(parent, 0o500))
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	d.remove(dir)
	assert.True(t, d.made[dir], "a directory that is still there must stay remembered")
	assert.DirExists(t, dir)

	require.NoError(t, os.Chmod(parent, 0o700))
	d.remove(dir)
	assert.False(t, d.made[dir])
	assert.NoDirExists(t, dir)

	// One that something else already removed is simply forgotten.
	gone := filepath.Join(parent, "gone")
	d.add(gone)
	d.remove(gone)
	assert.False(t, d.made[gone])
}
