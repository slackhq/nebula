//go:build !windows

package localapi

import (
	"context"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// ownGroup returns a group this process may hand a socket to: its own effective group,
// by name and by gid, which is the one chown accepts from an unprivileged user.
func ownGroup(t *testing.T) (name, gid string) {
	t.Helper()
	gid = strconv.Itoa(os.Getegid())
	g, err := user.LookupGroupId(gid)
	require.NoError(t, err)
	return g.Name, gid
}

func socketGroup(t *testing.T, path string) uint32 {
	t.Helper()
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return uint32(st.Gid)
}

// TestLookupGroupID: a group is named as the host names it or by its gid; a gid the
// host does not list is accepted as chown would accept it, and a name it does not list
// is a mistake to report.
func TestLookupGroupID(t *testing.T) {
	name, gid := ownGroup(t)

	got, err := lookupGroupID(name)
	require.NoError(t, err)
	assert.Equal(t, gid, got)

	got, err = lookupGroupID(gid)
	require.NoError(t, err)
	assert.Equal(t, gid, got)

	got, err = lookupGroupID("4000000000")
	require.NoError(t, err)
	assert.Equal(t, "4000000000", got)

	_, err = lookupGroupID("no-such-group-nebula-test")
	require.ErrorContains(t, err, "does not exist")
}

// TestControlAccessFromConfig: no group is the owner-only socket; a group is 0660 with
// that group; a group the host does not know is a config error naming the key.
func TestControlAccessFromConfig(t *testing.T) {
	name, gid := ownGroup(t)
	load := func(body string) (Access, error) {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(body))
		return controlAccessFrom(c)
	}

	acc, err := load("local_api: {}\n")
	require.NoError(t, err)
	assert.Equal(t, ownerOnly(), acc)

	acc, err = load("local_api:\n  control:\n    group: " + name + "\n")
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), acc.Mode)
	assert.Equal(t, name, acc.Group.Name)
	assert.Equal(t, gid, acc.Group.ID)

	_, err = load("local_api:\n  control:\n    group: no-such-group-nebula-test\n")
	require.ErrorContains(t, err, CtlGroupKey)
	assert.ErrorContains(t, err, "does not exist")
}

// TestControlSocketIsHandedToTheGroup: the socket is created with the group's gid and
// 0660, whatever the umask, and a reload that takes the group away tightens the socket
// in place, without moving it.
func TestControlSocketIsHandedToTheGroup(t *testing.T) {
	old := unix.Umask(0077)
	defer unix.Umask(old)

	name, gid := ownGroup(t)
	want, err := strconv.ParseUint(gid, 10, 32)
	require.NoError(t, err)

	s := NewServer(test.NewLogger(), basicRegistry())
	path := testSocket(t)
	require.NoError(t, s.Rebind(context.Background(), path, Access{Mode: 0660, Group: Group{Name: name, ID: gid}}))
	defer s.Stop()

	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), fi.Mode().Perm())
	assert.Equal(t, uint32(want), socketGroup(t, path))

	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	fi, err = os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
	assert.Equal(t, path, s.Path())

	_, err = (&Client{Path: path}).Describe()
	require.NoError(t, err, "the same listener is still serving")
}

// TestControlSocketWithAGroupTrustsTheKernel: with a group sharing the socket, the
// kernel's check on connect is the access control and the daemon's peer check stands
// aside, so a connection the peer check alone would refuse is served. Without a group
// the same connection is refused; see TestPeerCheckRefusesAnotherUser.
func TestControlSocketWithAGroupTrustsTheKernel(t *testing.T) {
	if !peerCheckSupported {
		t.Skip("no peer credentials on this platform")
	}
	name, gid := ownGroup(t)

	me := currentUID()
	asUID(t, me+1)
	s := NewServer(test.NewLogger(), basicRegistry())
	asUID(t, me)

	path := testSocket(t)
	require.NoError(t, s.Rebind(context.Background(), path, Access{Mode: 0660, Group: Group{Name: name, ID: gid}}))
	defer s.Stop()

	_, err := (&Client{Path: path}).Describe()
	require.NoError(t, err, "the socket's group admitted us; the peer check must not refuse")

	// Taking the group away on a reload puts the peer check back.
	require.NoError(t, s.Rebind(context.Background(), path, ownerOnly()))
	_, err = (&Client{Path: path}).Describe()
	require.ErrorContains(t, err, "not permitted")
}

// TestInfoAccessFromConfig: a group with no mode is 0660; a mode that gives the group
// nothing is refused, with the mode that would; an explicit mode with group bits is
// kept as given.
func TestInfoAccessFromConfig(t *testing.T) {
	name, gid := ownGroup(t)
	load := func(body string) (infoConfig, error) {
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(body))
		return infoConfigFrom(c)
	}
	section := func(extra string) string {
		return "local_api:\n  info:\n    enabled: true\n    socket: /run/nebula/info.sock\n" + extra
	}

	cfg, err := load(section("    group: " + name + "\n"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), cfg.Access.Mode)
	require.NotNil(t, cfg.Access.Group)
	assert.Equal(t, gid, cfg.Access.Group.ID)

	cfg, err = load(section("    group: " + name + "\n    socket_mode: \"0664\"\n"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0664), cfg.Access.Mode)

	_, err = load(section("    group: " + name + "\n    socket_mode: \"0600\"\n"))
	require.ErrorContains(t, err, "gives group "+name+" no access")
	require.ErrorContains(t, err, `"0660"`)

	cfg, err = load(section(""))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), cfg.Access.Mode)
	assert.Nil(t, cfg.Access.Group)
}

// TestSocketIsHandedToTheGroup: the socket is created with the group's gid and the
// mode, and a changed group or mode on a reload is applied to the socket in place.
func TestSocketIsHandedToTheGroup(t *testing.T) {
	name, gid := ownGroup(t)
	group := &Group{Name: name, ID: gid}
	want, err := strconv.ParseUint(gid, 10, 32)
	require.NoError(t, err)

	s, path := serveInfo(t, infoRegistry(), 0600)
	require.NoError(t, s.Rebind(context.Background(), path, Access{Mode: 0660, Group: group}))
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), fi.Mode().Perm())
	assert.Equal(t, uint32(want), socketGroup(t, path))

	status, _ := test.HTTPGet(t, path, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status, "the same listener is still serving")

	// The mode is the operator's to widen further.
	require.NoError(t, s.Rebind(context.Background(), path, Access{Mode: 0664, Group: group}))
	fi, err = os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0664), fi.Mode().Perm())
	assert.Equal(t, path, s.Path())
}

// TestRemovingTheGroupHandsTheSocketBack: a reload that drops the group key leaves the
// mode the operator set but returns the socket to the daemon's own group, so the old
// group's members are no longer admitted. The socket is first handed to a group this
// process belongs to other than its own, which not every host offers.
func TestRemovingTheGroupHandsTheSocketBack(t *testing.T) {
	own := os.Getegid()
	groups, err := os.Getgroups()
	require.NoError(t, err)
	other := -1
	for _, g := range groups {
		if g != own {
			other = g
			break
		}
	}
	if other < 0 {
		t.Skip("this process belongs to no group but its own")
	}
	gid := strconv.Itoa(other)

	s := NewServer(test.NewLogger(), basicRegistry())
	path := testSocket(t)
	require.NoError(t, s.Rebind(context.Background(), path, Access{Mode: 0660, Group: Group{Name: gid, ID: gid}}))
	defer s.Stop()
	assert.Equal(t, uint32(other), socketGroup(t, path))

	require.NoError(t, s.Rebind(context.Background(), path, Access{Mode: 0660}))
	assert.Equal(t, uint32(own), socketGroup(t, path), "the daemon's own group again")
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), fi.Mode().Perm(), "the mode is the operator's")
}
