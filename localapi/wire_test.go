//go:build !windows

package localapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWireRecoversFromBadPathAtStartup covers a socket path that is unusable when nebula
// starts. The operator's fix is a config edit and a reload, so the reload has to be able
// to bring up a socket that never existed, not only move one that does.
func TestWireRecoversFromBadPathAtStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(fmt.Sprintf("local_api:\n  control:\n    socket: /%s\n", strings.Repeat("x", sunPathMax))))

	srv := Wire(ctx, test.NewLogger(), c, basicRegistry()).Control
	t.Cleanup(srv.Stop)
	assert.Empty(t, srv.Path(), "an over-long path must not produce a socket")

	good := testSocket(t)
	require.NoError(t, c.ReloadConfigString(fmt.Sprintf("local_api:\n  control:\n    socket: %s\n", good)).Err)

	assert.Equal(t, good, srv.Path())
	out, errText := run(t, good, "echo", "hi")
	assert.Empty(t, errText)
	assert.Equal(t, "[hi]", out)
}

// TestRebindAfterReloadBoundTheSocket covers a HUP that lands inside Wire, after the
// reload callback is registered and before the first attempt runs. The callback does the
// first bind; the attempt must then find the socket it was about to create already up
// and leave it, not fail or rebind it, which would have Wire warn that commands are
// unavailable while they are.
func TestRebindAfterReloadBoundTheSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	path := testSocket(t)
	cfg := fmt.Sprintf("local_api:\n  control:\n    socket: %s\n", path)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(cfg))

	srv := NewServer(test.NewLogger(), basicRegistry())
	t.Cleanup(srv.Stop)

	// Wire's first half, then the HUP.
	followControlConfig(ctx, test.NewLogger(), c, srv)
	require.NoError(t, c.ReloadConfigString(cfg).Err)
	require.Equal(t, path, srv.Path(), "the reload callback does the first bind")

	// Wire's second half.
	require.NoError(t, srv.Rebind(ctx, path, ownerOnly()))
	assert.Equal(t, path, srv.Path())
	out, errText := run(t, path, "echo", "hi")
	assert.Empty(t, errText)
	assert.Equal(t, "[hi]", out)
}

// TestWireRetriesAFailedMoveOnPlainReload covers a move whose bind fails for a reason
// outside the config: the key names a path under a runtime directory that is not there
// yet. The daemon keeps the old socket, but the client reads the new path from the same
// file and cannot reach it, so the operator creates the directory and reloads. The key
// has not changed since the move was asked for, and the reload still has to make it.
func TestWireRetriesAFailedMoveOnPlainReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	section := func(path string) string {
		return fmt.Sprintf("local_api:\n  control:\n    socket: %s\n", path)
	}
	first := testSocket(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(section(first)))

	srv := Wire(ctx, test.NewLogger(), c, basicRegistry()).Control
	t.Cleanup(srv.Stop)
	require.Equal(t, first, srv.Path())

	runtimeDir := filepath.Join(privateBase(t), "run")
	moved := filepath.Join(runtimeDir, DirName, "s.sock")
	require.NoError(t, c.ReloadConfigString(section(moved)).Err)
	assert.Equal(t, first, srv.Path(), "a move that cannot bind keeps the socket it had")

	require.NoError(t, os.Mkdir(runtimeDir, 0700))
	require.NoError(t, c.ReloadConfigString(section(moved)).Err)
	require.False(t, c.HasChanged(CtlSocketKey), "the config is the same; the fix was on disk")

	assert.Equal(t, moved, srv.Path())
	_, err := os.Stat(first)
	assert.True(t, os.IsNotExist(err), "the old socket is given up once the move binds")
	out, errText := run(t, moved, "echo", "hi")
	assert.Empty(t, errText)
	assert.Equal(t, "[hi]", out)
}

// TestWireRecoversOnPlainReloadAfterBadBind covers a path that is fine but a bind that
// is not: the runtime directory is missing when nebula starts. The fix is made outside
// the config, so the config does not change; a plain reload still has to bring the
// socket up.
func TestWireRecoversOnPlainReloadAfterBadBind(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	base := privateBase(t)
	runtimeDir := filepath.Join(base, "run")
	path := filepath.Join(runtimeDir, DirName, "s.sock")
	cfg := fmt.Sprintf("local_api:\n  control:\n    socket: %s\n", path)

	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(cfg))

	srv := Wire(ctx, test.NewLogger(), c, basicRegistry()).Control
	t.Cleanup(srv.Stop)
	assert.Empty(t, srv.Path(), "listen creates one level only, so a missing runtime dir fails the bind")

	require.NoError(t, os.Mkdir(runtimeDir, 0700))
	require.NoError(t, c.ReloadConfigString(cfg).Err)
	require.False(t, c.HasChanged(CtlSocketKey), "the config is the same; the fix was on disk")

	assert.Equal(t, path, srv.Path())
	out, errText := run(t, path, "echo", "hi")
	assert.Empty(t, errText)
	assert.Equal(t, "[hi]", out)

	// And a reload with a socket up and no change in the key is still a no-op.
	require.NoError(t, c.ReloadConfigString(cfg).Err)
	assert.Equal(t, path, srv.Path())
	out, errText = run(t, path, "echo", "still")
	assert.Empty(t, errText)
	assert.Equal(t, "[still]", out)
}

// TestWireControlCanBeDisabled: local_api.control.enabled false serves no socket, and
// the key follows reloads both ways. With the control socket off, its path is free for
// the info API to use.
func TestWireControlCanBeDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	path := testSocket(t)
	section := func(enabled bool) string {
		return fmt.Sprintf("local_api:\n  control:\n    enabled: %t\n    socket: %s\n", enabled, path)
	}

	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(section(false)))
	eps := Wire(ctx, test.NewLogger(), c, basicRegistry())
	t.Cleanup(eps.Stop)
	srv := eps.Control
	assert.Empty(t, srv.Path())
	_, err := os.Lstat(path)
	assert.True(t, os.IsNotExist(err), "no socket is bound")

	require.NoError(t, c.ReloadConfigString(section(true)).Err)
	assert.Equal(t, path, srv.Path())
	out, errText := run(t, path, "echo", "on")
	assert.Empty(t, errText)
	assert.Equal(t, "[on]", out)

	require.NoError(t, c.ReloadConfigString(section(false)).Err)
	assert.Empty(t, srv.Path())
	_, err = os.Lstat(path)
	assert.True(t, os.IsNotExist(err), "the socket is removed")

	require.NoError(t, c.ReloadConfigString(section(false)+fmt.Sprintf("  info:\n    enabled: true\n    socket: %s\n", path)).Err)
	assert.Equal(t, path, eps.Info.Path(), "a disabled control socket does not hold its path")
}

// TestWireRefusesOnePathForBothAPIs: a config that gives the control socket and the info
// API one path is refused by both sides, from the configured paths, so it is caught
// however the binds would have ordered themselves. Moving one off the path on a reload
// brings both up.
func TestWireRefusesOnePathForBothAPIs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	section := func(ctl, info string) string {
		return fmt.Sprintf("local_api:\n  control:\n    socket: %s\n  info:\n    enabled: true\n    socket: %s\n", ctl, info)
	}
	shared := testSocket(t)
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(section(shared, shared)))

	eps := Wire(ctx, test.NewLogger(), c, basicRegistry())
	t.Cleanup(eps.Stop)
	assert.Empty(t, eps.Control.Path(), "the control socket does not take the info API's path")
	assert.Empty(t, eps.Info.Path(), "the info API does not take the control socket's path")
	_, err := os.Stat(shared)
	assert.True(t, os.IsNotExist(err), "neither side bound the shared path")

	// A reload that moves the control socket onto the info API's path is refused the same
	// way, and the control socket keeps the one it has.
	other := testSocket(t)
	require.NoError(t, c.ReloadConfigString(section(other, shared)).Err)
	require.Equal(t, other, eps.Control.Path())
	require.Equal(t, shared, eps.Info.Path())

	require.NoError(t, c.ReloadConfigString(section(shared, shared)).Err)
	assert.Equal(t, other, eps.Control.Path(), "a move onto the info API's path keeps the current socket")
	assert.Equal(t, shared, eps.Info.Path())
}
