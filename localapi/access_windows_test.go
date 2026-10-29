//go:build windows

package localapi

import (
	"bytes"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TestLookupGroupIDOnWindows: an account name resolves to its SID, a SID written out
// is accepted as it is, and an account the host does not know is reported.
func TestLookupGroupIDOnWindows(t *testing.T) {
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	require.NoError(t, err)

	got, err := lookupGroupID("Users")
	require.NoError(t, err)
	assert.Equal(t, users.String(), got)

	got, err = lookupGroupID(users.String())
	require.NoError(t, err)
	assert.Equal(t, users.String(), got)

	_, err = lookupGroupID("no-such-account-nebula-test")
	require.ErrorContains(t, err, "does not exist")
}

// TestSDDLAdmitsTheGroup: the descriptor is the owner, SYSTEM and Administrators with
// full access, plus the group with what a client needs and nothing generic, so a
// member cannot create an instance of the pipe; see pipeClientAccess.
func TestSDDLAdmitsTheGroup(t *testing.T) {
	sddl, err := sddlFor(OwnerOnly())
	require.NoError(t, err)
	assert.NotContains(t, sddl, "S-1-5-32-545")

	sddl, err = sddlFor(Access{mode: groupSocketMode, group: Group{name: "Users", id: "S-1-5-32-545"}})
	require.NoError(t, err)
	assert.Contains(t, sddl, "(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120083;;;S-1-5-32-545)")
	assert.Zero(t, pipeClientAccess&windows.FILE_APPEND_DATA, "FILE_APPEND_DATA is FILE_CREATE_PIPE_INSTANCE on a pipe")
	assert.Zero(t, pipeClientAccess&(windows.GENERIC_READ|windows.GENERIC_WRITE|windows.GENERIC_ALL))
}

// TestWarnUnprotectedName: a pipe outside the protected namespace is warned about,
// since anyone could have created the name first; one under it, however spelled, is not.
func TestWarnUnprotectedName(t *testing.T) {
	logs := &bytes.Buffer{}
	l := test.NewLoggerWithOutput(logs)
	warnUnprotectedName(l, DefaultSocketPath)
	warnUnprotectedName(l, `\\.\PIPE\protectedprefix\administrators\nebula-info`)
	assert.Empty(t, logs.String())
	warnUnprotectedName(l, `\\.\pipe\nebula-info`)
	assert.Contains(t, logs.String(), protectedPrefix)
}
