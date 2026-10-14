//go:build !windows

package localapi

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// privateBase returns a short directory of our own, 0700, for tests to lay sockets out
// under, short enough that a path under it fits sun_path.
func privateBase(t *testing.T) string {
	t.Helper()
	return test.ShortTempDir(t)
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
	require.NoError(t, s.Rebind(context.Background(), filepath.Join(dir, "s.sock"), ownerOnly()))
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
	require.NoError(t, s.Rebind(context.Background(), filepath.Join(base, DirName, "s.sock"), ownerOnly()))
	s.Stop()

	dir := filepath.Join(base, "missing", DirName)
	err := s.Rebind(context.Background(), filepath.Join(dir, "s.sock"), ownerOnly())
	require.Error(t, err)
	require.ErrorContains(t, err, "could not create "+dir)
	assert.NoDirExists(t, filepath.Join(base, "missing"))
}

// TestListenRestoresTheUmask: listen tightens the process umask around bind so the socket
// node is never created looser than 0600. That is process wide state, so it must come
// back exactly as it was, on success and on failure alike.
func TestListenRestoresTheUmask(t *testing.T) {
	old := syscall.Umask(0022)
	t.Cleanup(func() { syscall.Umask(old) })

	base := privateBase(t)
	ln, err := listen(filepath.Join(base, DirName, "s.sock"), ownerOnly())
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	assert.Equal(t, 0022, syscall.Umask(0022), "umask after a successful listen")

	_, err = listen(filepath.Join(base, DirName, "s.sock"), ownerOnly())
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
	require.NoError(t, s.Rebind(context.Background(), filepath.Join(dir, "ctl.sock"), ownerOnly()))
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
	err := s.Rebind(context.Background(), filepath.Join(long, "s.sock"), ownerOnly())

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

// TestNamedPathIsUsedAsGiven: a path the operator named is served from, and dialed,
// wherever it is, a directory other users can write to included; the socket's own mode
// is what keeps them out.
func TestNamedPathIsUsedAsGiven(t *testing.T) {
	base := privateBase(t)
	path := filepath.Join(openDir(t, base), DirName, "s.sock")

	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
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

// TestClientSaysWhenTheReplyCannotBeRead: something answered on the socket, but not
// with a response. That is reported as a reply that could not be read, which is what
// it is, and not as a failure to reach the daemon, whether the other side read the
// request first or hung up on it: a daemon that is not nebula may do either.
func TestClientSaysWhenTheReplyCannotBeRead(t *testing.T) {
	for _, readsFirst := range []bool{true, false} {
		path := testSocket(t)
		require.NoError(t, os.Mkdir(filepath.Dir(path), 0700))
		ln, err := net.Listen(network, path)
		require.NoError(t, err)
		require.NoError(t, os.Chmod(path, 0600))

		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if readsFirst {
				_, _ = bufio.NewReader(c).ReadBytes('\n')
			}
			_, _ = c.Write([]byte("this is not a response\n"))
			c.Close()
		}()

		_, err = (&Client{Path: path}).Describe()
		var unread *ReplyError
		require.ErrorAs(t, err, &unread, "reads first: %v", readsFirst)
		assert.Contains(t, err.Error(), "the daemon's reply could not be read")
		ln.Close()
	}
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
	require.ErrorContains(t, err, "did not answer within")
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

// TestPeerCheckRefusesAnotherUser: a server built as one user and serving as another
// refuses the real user at the peer check, and the refusal reaches the client as the
// daemon's answer rather than as a failure to reach it.
func TestPeerCheckRefusesAnotherUser(t *testing.T) {
	if !peerCheckSupported {
		t.Skip("no peer credentials on this platform")
	}

	me := currentUID()
	asUID(t, me+1)
	s := NewServer(test.NewLogger(), basicRegistry())
	asUID(t, me)

	path := testSocket(t)
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	defer s.Stop()

	_, err := (&Client{Path: path}).Describe()
	require.Error(t, err)
	require.ErrorContains(t, err, "not permitted")
	var refused *DaemonError
	assert.ErrorAs(t, err, &refused, "the daemon answered; this is not a reachability failure")
}

// TestListenerDoesNotUnlinkOnClose: the server unlinks its socket node itself, before
// the listener closes, and the listener must not unlink again afterwards. By the time a
// close happens the path may belong to a newer daemon that found the node stale and
// bound its own, and a second unlink would take that daemon's socket from under it.
func TestListenerDoesNotUnlinkOnClose(t *testing.T) {
	path := filepath.Join(privateBase(t), DirName, "s.sock")
	old, err := listen(path, ownerOnly())
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

// TestRebindRecreatesASocketRemovedFromUnderIt: logind clearing /run/user/<uid> on
// logout, or a unit cleaning a RuntimeDirectory= it shares, takes the node away while
// the listener stays open and unreachable. The next reload, which Rebinds onto the same
// path, has to notice and bind the socket again rather than return early because the
// path has not changed.
func TestRebindRecreatesASocketRemovedFromUnderIt(t *testing.T) {
	path := testSocket(t)
	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	t.Cleanup(s.Stop)

	require.NoError(t, os.Remove(path))
	_, err := (&Client{Path: path}).Describe()
	require.Error(t, err, "nothing can reach the daemon with its node gone")

	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	assert.Equal(t, path, s.Path())
	_, err = (&Client{Path: path}).Describe()
	require.NoError(t, err, "the plain reload brought the socket back")

	// And a Rebind with the socket in place is still a no-op.
	before, ok := identifySocket(path)
	require.True(t, ok)
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	after, _ := identifySocket(path)
	assert.Equal(t, before, after, "the node was left alone")
}

// TestStopLeavesAStrangersSocketAlone: once our node has been taken from under us and
// another daemon has bound the path, the node there is that daemon's, and our Stop must
// not unlink it by path.
func TestStopLeavesAStrangersSocketAlone(t *testing.T) {
	path := testSocket(t)
	s := NewServer(test.NewLogger(), basicRegistry())
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))

	require.NoError(t, os.Remove(path))
	other, err := net.Listen(network, path)
	require.NoError(t, err)
	t.Cleanup(func() { other.Close() })

	s.Stop()
	_, err = os.Stat(path)
	assert.NoError(t, err, "the newer daemon's socket is still in place")
}

// TestListenRefusesADirectoryOthersCanWrite: whoever can write the socket's directory
// can put a socket of their own at the path and answer the clients, who trust the path;
// so a directory writable by its group or by everyone is refused, and nothing is bound.
func TestListenRefusesADirectoryOthersCanWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0775, 0757, 0777, 01777} {
		dir := filepath.Join(privateBase(t), "loose")
		require.NoError(t, os.Mkdir(dir, mode))
		require.NoError(t, os.Chmod(dir, mode))

		_, err := listen(filepath.Join(dir, "s.sock"), ownerOnly())
		require.ErrorContains(t, err, "writable by", "mode %04o", mode)
		assert.NoFileExists(t, filepath.Join(dir, "s.sock"))
	}
}

// TestListenRefusesADirectoryOwnedBySomebodyElse: a directory that is neither ours nor
// root's is refused, since its owner could replace the socket. The test's own directory
// stands in for somebody else's by the process pretending to be another user.
func TestListenRefusesADirectoryOwnedBySomebodyElse(t *testing.T) {
	me := currentUID()
	if me == 0 {
		t.Skip("root's directories are accepted whoever is asking")
	}
	dir := filepath.Join(privateBase(t), "theirs")
	require.NoError(t, os.Mkdir(dir, 0755))

	asUID(t, me+1)
	_, err := listen(filepath.Join(dir, "s.sock"), ownerOnly())
	require.ErrorContains(t, err, "is owned by")
	assert.NoFileExists(t, filepath.Join(dir, "s.sock"))

	asUID(t, me)
	ln, err := listen(filepath.Join(dir, "s.sock"), ownerOnly())
	require.NoError(t, err, "the same directory, seen as our own, serves")
	release(ln, filepath.Join(dir, "s.sock"), socketID{})
}

// TestListenThroughASymlinkedDirectory: a link where the directory should be is judged
// by who owns it, since they decide where the path leads, and then by the directory it
// resolves to. Our own link to a proper directory serves, as /var/run on linux is root's
// link to /run; somebody else's link is refused, and so is a link of ours to a directory
// others can write.
func TestListenThroughASymlinkedDirectory(t *testing.T) {
	me := currentUID()
	if me == 0 {
		t.Skip("root's links are accepted whoever is asking")
	}
	base := privateBase(t)
	real := filepath.Join(base, "real")
	require.NoError(t, os.Mkdir(real, 0755))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(real, link))
	path := filepath.Join(link, "s.sock")

	ln, err := listen(path, ownerOnly())
	require.NoError(t, err, "our link to our directory")
	release(ln, path, socketID{})
	assert.NoFileExists(t, filepath.Join(real, "s.sock"))

	asUID(t, me+1)
	_, err = listen(path, ownerOnly())
	require.ErrorContains(t, err, "is a symlink owned by")
	asUID(t, me)

	require.NoError(t, os.Chmod(real, 0777))
	_, err = listen(path, ownerOnly())
	require.ErrorContains(t, err, "writable by everyone")
}

// TestListenRefusesASymlinkAtThePath: a link where the socket should be is somebody
// else's doing, and it is refused before bind rather than followed. bind(2) on darwin
// follows a dangling link and creates the socket at its target, and the chmod after it
// would follow a link to anything, so neither the target nor the link is touched.
func TestListenRefusesASymlinkAtThePath(t *testing.T) {
	path := testSocket(t)
	require.NoError(t, os.Mkdir(filepath.Dir(path), 0700))
	target := filepath.Join(filepath.Dir(path), "target")

	require.NoError(t, os.Symlink(target, path))
	_, err := listen(path, Access{Mode: 0666})
	require.ErrorContains(t, err, "is not a socket")
	_, statErr := os.Lstat(target)
	assert.True(t, os.IsNotExist(statErr), "a dangling link's target is not created")

	require.NoError(t, os.WriteFile(target, nil, 0600))
	_, err = listen(path, Access{Mode: 0666})
	require.ErrorContains(t, err, "is not a socket")
	fi, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(), "the file the link names keeps its mode")
	assert.True(t, fi.Mode().IsRegular())
}

// TestChmodSocketRefusesWhatIsNotOurSocket: the mode is set through a look that does not
// follow links, so a link, a plain file, or a socket of another user's at the path is
// reported instead of chmoded. The last is seen as another user by changing who we are.
func TestChmodSocketRefusesWhatIsNotOurSocket(t *testing.T) {
	dir := filepath.Join(privateBase(t), "n")
	require.NoError(t, os.Mkdir(dir, 0700))

	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, nil, 0600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(file, link))

	require.ErrorContains(t, applyAccess(link, Access{Mode: 0666}), "a symlink")
	require.ErrorContains(t, applyAccess(file, Access{Mode: 0666}), "a regular file")
	fi, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())

	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen(network, sock)
	require.NoError(t, err)
	defer ln.Close()
	require.NoError(t, applyAccess(sock, Access{Mode: 0660}))
	fi, err = os.Stat(sock)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), fi.Mode().Perm())

	asUID(t, currentUID()+1)
	require.ErrorContains(t, applyAccess(sock, Access{Mode: 0666}), "not by us")
	fi, err = os.Stat(sock)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), fi.Mode().Perm())
}
