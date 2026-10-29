//go:build windows

package localapi

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TestOwnerAccepted pins which accounts may answer a nebula ctl request: the client's
// own, and the accounts a daemon runs as that an ordinary user cannot create an object
// owned by. Any other user is refused, since any user can create any pipe name.
func TestOwnerAccepted(t *testing.T) {
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)

	wellKnown := func(typ windows.WELL_KNOWN_SID_TYPE) *windows.SID {
		sid, err := windows.CreateWellKnownSid(typ)
		require.NoError(t, err)
		return sid
	}
	parse := func(s string) *windows.SID {
		sid, err := windows.StringToSid(s)
		require.NoError(t, err)
		return sid
	}

	accepted := map[string]*windows.SID{
		"self":           me.User.Sid,
		"SYSTEM":         wellKnown(windows.WinLocalSystemSid),
		"Administrators": wellKnown(windows.WinBuiltinAdministratorsSid),
	}
	for name, sid := range accepted {
		assert.True(t, ownerAccepted(sid, me.User.Sid), name)
	}

	refused := map[string]*windows.SID{
		"Everyone":                wellKnown(windows.WinWorldSid),
		"Users":                   wellKnown(windows.WinBuiltinUsersSid),
		"another user":            parse("S-1-5-21-1-2-3-1001"),
		"a service's own account": parse("S-1-5-80-1-2-3-4-5"),
		"LocalService":            wellKnown(windows.WinLocalServiceSid),
	}
	for name, sid := range refused {
		assert.False(t, ownerAccepted(sid, me.User.Sid), name)
	}
}

// TestCheckSocketPathRefusesASpellingTheKernelWouldRewrite: a \\.\ path is normalized
// before the pipe filesystem sees it, so a name with a forward slash or a . or ..
// component would be created somewhere other than where its spelling says, and the
// protected-prefix check would judge the spelling. Such a name is a config error.
func TestCheckSocketPathRefusesASpellingTheKernelWouldRewrite(t *testing.T) {
	for _, ok := range []string{
		DefaultSocketPath,
		`\\.\pipe\nebula-info`,
		`\\.\pipe\ProtectedPrefix\Administrators\nebula-info`,
		`\\.\pipe\with.dots\and..more`,
	} {
		assert.NoError(t, checkSocketPath(InfoSocketKey, ok), ok)
	}
	for _, bad := range []string{
		`\\.\pipe\ProtectedPrefix\Administrators\..\..\nebula-info`,
		`\\.\pipe\ProtectedPrefix/Administrators/nebula-info`,
		`\\.\pipe\.\nebula-info`,
		`\\.\pipe\\nebula-info`,
		`\\.\pipe\nebula-info\`,
		`\\.\pipe\`,
		`/var/run/nebula/info.sock`,
	} {
		err := checkSocketPath(InfoSocketKey, bad)
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), InfoSocketKey, bad)
	}
}

// TestSamePathIgnoresCase: pipe names are case-insensitive to the kernel, so a reload
// that only respells one is not a move.
func TestSamePathIgnoresCase(t *testing.T) {
	assert.True(t, samePath(`\\.\pipe\Nebula-Info`, `\\.\pipe\nebula-info`))
	assert.False(t, samePath(`\\.\pipe\nebula-info`, `\\.\pipe\nebula-ctl`))
}

// TestAccessChangedIgnoresTheMode: only the group is in a pipe's security descriptor.
func TestAccessChangedIgnoresTheMode(t *testing.T) {
	g := Group{name: "Users", id: "S-1-5-32-545"}
	assert.False(t, accessChanged(Access{mode: 0660, group: g}, Access{mode: 0666, group: g}))
	assert.True(t, accessChanged(Access{mode: 0660, group: g}, Access{mode: 0660}))
	assert.True(t, accessChanged(Access{mode: 0600}, Access{mode: 0600, group: g}))
}

// TestDefaultPathIsProtected pins the default name to the namespace only administrators
// and SYSTEM can create under, which is what lets nebula ctl trust the default name
// from its spelling alone.
func TestDefaultPathIsProtected(t *testing.T) {
	p := DefaultSocketPath
	assert.True(t, isProtectedPath(p), p)
	assert.Equal(t, `\\.\pipe\ProtectedPrefix\Administrators\nebula-ctl`, p)
}

// TestConfiguredPipeNameMustBeFull: a configured name is used as given, and only a full
// pipe name means anything here.
func TestConfiguredPipeNameMustBeFull(t *testing.T) {
	p, err := SocketPathFromConfig(fakeWinConfig{CtlSocketKey: `\\.\pipe\nebula-ctl`})
	require.NoError(t, err)
	assert.Equal(t, `\\.\pipe\nebula-ctl`, p)

	for _, bad := range []string{"nebula-ctl", `C:\nebula\ctl.sock`, `\\.\pipe\`} {
		_, err := SocketPathFromConfig(fakeWinConfig{CtlSocketKey: bad})
		require.Error(t, err, bad)
		assert.ErrorContains(t, err, "full pipe name", bad)
	}
}

type fakeWinConfig map[string]string

func (f fakeWinConfig) GetString(k, d string) string {
	if v, ok := f[k]; ok {
		return v
	}
	return d
}

func TestIsProtectedPath(t *testing.T) {
	assert.True(t, isProtectedPath(`\\.\pipe\ProtectedPrefix\Administrators\nebula-1`))
	assert.True(t, isProtectedPath(`\\.\pipe\protectedprefix\administrators\nebula-1`), "pipe names are case insensitive")
	assert.False(t, isProtectedPath(`\\.\pipe\ProtectedPrefix\Administrators\`), "the prefix alone names nothing")
	assert.False(t, isProtectedPath(`\\.\pipe\nebula-1`))
	assert.False(t, isProtectedPath(`\\.\pipe\ProtectedPrefix\Users\nebula-1`))
}

// TestListenRefused pins how a failed create is reported. Access denied under the
// protected prefix is the namespace refusing a non-administrator, and says so; the same
// error for an administrator, or for any name outside the prefix, is a name some other
// process holds, and is errEndpointHeld so the daemon logs it as an error.
func TestListenRefused(t *testing.T) {
	protected := `\\.\pipe\ProtectedPrefix\Administrators\nebula-1`
	plain := `\\.\pipe\nebula-1`

	err := listenRefused(protected, false, windows.ERROR_ACCESS_DENIED)
	assert.NotErrorIs(t, err, errEndpointHeld)
	assert.ErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
	assert.Contains(t, err.Error(), "requires an administrator")
	assert.Contains(t, err.Error(), protectedPrefix)

	assert.ErrorIs(t, listenRefused(protected, true, windows.ERROR_ACCESS_DENIED), errEndpointHeld)
	assert.ErrorIs(t, listenRefused(plain, false, windows.ERROR_ACCESS_DENIED), errEndpointHeld)
	assert.ErrorIs(t, listenRefused(protected, false, windows.ERROR_ALREADY_EXISTS), errEndpointHeld)
	assert.ErrorIs(t, listenRefused(plain, true, windows.ERROR_ALREADY_EXISTS), errEndpointHeld)

	other := errors.New("something else")
	assert.Same(t, other, listenRefused(protected, false, other))
}

// TestListenProtectedName creates and dials a name under the protected prefix. It needs
// an administrator, and otherwise checks only that the refusal is the one listen
// promises a non-administrator.
func TestListenProtectedName(t *testing.T) {
	path := protectedPrefix + "nebula-test-" + t.Name()
	ln, err := listen(path, OwnerOnly())
	if !isAdministrator() {
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires an administrator")
		t.Skip("not an administrator; the protected namespace refused the create as it should")
	}
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
		accepted <- err
	}()

	conn, err := dial(path, time.Second)
	require.NoError(t, err)
	conn.Close()
	require.NoError(t, <-accepted)
}

// TestDialAcceptsOwnPipe dials a pipe this process created outside the protected
// prefix, as an override might name, which the owner check must pass: the pipe's owner
// is this account, or Administrators when the test is elevated.
func TestDialAcceptsOwnPipe(t *testing.T) {
	path := pipePrefix + "nebula-test-" + t.Name()
	ln, err := listen(path, OwnerOnly())
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
		accepted <- err
	}()

	conn, err := dial(path, time.Second)
	require.NoError(t, err)
	conn.Close()
	require.NoError(t, <-accepted)
}

// TestListenRefusesHeldName pins that a name another listener already holds is refused
// with errEndpointHeld rather than joined, which is what keeps an impostor from being
// served alongside, or in place of, the daemon.
func TestListenRefusesHeldName(t *testing.T) {
	path := pipePrefix + "nebula-test-" + t.Name()
	first, err := listen(path, OwnerOnly())
	require.NoError(t, err)
	t.Cleanup(func() { first.Close() })

	var second net.Listener
	second, err = listen(path, OwnerOnly())
	if second != nil {
		second.Close()
	}
	require.ErrorIs(t, err, errEndpointHeld)
}
