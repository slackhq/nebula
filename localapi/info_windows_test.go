//go:build windows

package localapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TestInfoIsServedOnAPipe: the info API serves HTTP on a named pipe, whose security
// descriptor is its access control the way a socket's mode is on unix; a group named
// in the config is admitted by it.
func TestInfoIsServedOnAPipe(t *testing.T) {
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	require.NoError(t, err)
	group := Group{Name: "Users", ID: users.String()}

	s := NewInfoServer(test.NewLogger(), stubInfoHandler())
	path := pipePrefix + "nebula-info-test"
	require.NoError(t, s.Rebind(context.Background(), path, Access{Mode: groupSocketMode, Group: group}))
	t.Cleanup(s.Stop)
	assert.Equal(t, path, s.Path())

	client := &http.Client{Transport: &http.Transport{
		// What a program on the host has to do: ask for the data rights alone, since the
		// group is granted no more; see pipeClientAccess.
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return winio.DialPipeAccess(ctx, path, pipeClientAccess)
		},
	}}
	res, err := client.Get("http://nebula/v1/whoami")
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, string(body), `"me"`)

	// A change of group means a new pipe under the same name, still serving.
	require.NoError(t, s.Rebind(context.Background(), path, Access{Mode: groupSocketMode}))
	res, err = client.Get("http://nebula/v1/whoami")
	require.NoError(t, err)
	res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
}
