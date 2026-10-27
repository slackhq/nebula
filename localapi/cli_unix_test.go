//go:build !windows

package localapi

import (
	"bytes"
	"io"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInvokeLine covers output, -h, refusals in text and JSON, parse errors and an
// unreachable socket against a live server.
func TestInvokeLine(t *testing.T) {
	reg := basicRegistry()
	reg.Register(&commands.Command{
		Name: "refuse",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Failed("not today"), nil
		},
	})
	_, path := serve(t, reg)
	client := &Client{Path: path}
	var refused *DaemonError

	out, err := client.InvokeLine([]string{"echo", "-json", "a", "b"}, "nebula ctl", io.Discard)
	require.NoError(t, err)
	assert.Equal(t, `"[a b]"`, out)

	var help bytes.Buffer
	out, err = client.InvokeLine([]string{"echo", "-h"}, "nebula ctl", &help)
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Contains(t, help.String(), "echoes its arguments")

	out, err = client.InvokeLine([]string{"refuse"}, "nebula ctl", io.Discard)
	require.ErrorAs(t, err, &refused)
	assert.Contains(t, refused.Msg, "not today")
	assert.Empty(t, out)

	out, err = client.InvokeLine([]string{"refuse", "-json"}, "nebula ctl", io.Discard)
	require.ErrorAs(t, err, &refused)
	assert.Contains(t, out, "not today")

	_, err = client.InvokeLine([]string{"echo", "-nope"}, "dnclient ctl", io.Discard)
	require.ErrorContains(t, err, "see 'dnclient ctl echo -h'")
	assert.NotErrorAs(t, err, &refused)

	missing := testSocket(t)
	_, err = (&Client{Path: missing}).InvokeLine([]string{"echo"}, "nebula ctl", io.Discard)
	require.ErrorContains(t, err, "could not reach the control socket at "+missing)
	assert.NotErrorAs(t, err, &refused)
}
