//go:build !windows

package nebula

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/diag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCtlServer(t *testing.T) (*ctlServer, *config.C) {
	t.Helper()
	l := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	return &ctlServer{
		l:   l,
		ctx: ctx,
		srv: diag.NewServer(l, diag.NewRegistry()),
	}, config.NewC(l)
}

func setCtlConfig(c *config.C, m map[string]any) {
	c.Settings["ctl"] = m
}

func currentCtlRuntime(s *ctlServer) *ctlRuntime {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.run
}

// testCtlSocket returns a short socket path, see the note in diag/server_test.go about
// sun_path on darwin.
func testCtlSocket(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "nebctl")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return filepath.Join(dir, "ctl.sock")
}

func startCtl(t *testing.T, s *ctlServer) chan struct{} {
	t.Helper()

	done := make(chan struct{})
	go func() {
		s.Start()
		close(done)
	}()
	return done
}

func requireCtlStopped(t *testing.T, done chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ctl Start did not return after Stop")
	}
}

func TestCtlServer_loadConfig(t *testing.T) {
	t.Run("defaults to enabled at the platform path", func(t *testing.T) {
		_, c := newTestCtlServer(t)

		cfg, err := loadCtlConfig(c)
		require.NoError(t, err)
		assert.True(t, cfg.enabled)
		assert.Equal(t, diag.DefaultSocketPath(), cfg.socket)
		assert.False(t, cfg.explicit)
	})

	t.Run("an operator chosen path is recorded as explicit", func(t *testing.T) {
		_, c := newTestCtlServer(t)
		setCtlConfig(c, map[string]any{"socket": "/run/somewhere/ctl.sock"})

		cfg, err := loadCtlConfig(c)
		require.NoError(t, err)
		assert.Equal(t, "/run/somewhere/ctl.sock", cfg.socket)
		assert.True(t, cfg.explicit)
	})

	t.Run("a relative path is rejected", func(t *testing.T) {
		_, c := newTestCtlServer(t)
		setCtlConfig(c, map[string]any{"socket": "ctl.sock"})

		_, err := loadCtlConfig(c)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be an absolute path")
	})

	t.Run("a relative path is not rejected when ctl is off", func(t *testing.T) {
		_, c := newTestCtlServer(t)
		setCtlConfig(c, map[string]any{"enabled": false, "socket": "ctl.sock"})

		_, err := loadCtlConfig(c)
		assert.NoError(t, err)
	})
}

func TestCtlServer_reload(t *testing.T) {
	t.Run("the initial reload records config without listening", func(t *testing.T) {
		s, c := newTestCtlServer(t)
		setCtlConfig(c, map[string]any{"socket": testCtlSocket(t)})

		require.NoError(t, s.reload(c, true))
		assert.Nil(t, currentCtlRuntime(s), "Control.Start is what starts listening")
	})

	t.Run("enabling on reload starts listening", func(t *testing.T) {
		s, c := newTestCtlServer(t)
		path := testCtlSocket(t)
		setCtlConfig(c, map[string]any{"enabled": false, "socket": path})
		require.NoError(t, s.reload(c, true))

		setCtlConfig(c, map[string]any{"enabled": true, "socket": path})
		require.NoError(t, s.reload(c, false))

		waitFor(t, func() bool { return currentCtlRuntime(s) != nil })
		assert.FileExists(t, path)

		s.Stop()
	})

	t.Run("disabling on reload stops listening and unlinks", func(t *testing.T) {
		s, c := newTestCtlServer(t)
		path := testCtlSocket(t)
		setCtlConfig(c, map[string]any{"enabled": true, "socket": path})
		require.NoError(t, s.reload(c, true))

		done := startCtl(t, s)
		waitFor(t, func() bool { return currentCtlRuntime(s) != nil })

		setCtlConfig(c, map[string]any{"enabled": false, "socket": path})
		require.NoError(t, s.reload(c, false))

		requireCtlStopped(t, done)
		assert.Nil(t, currentCtlRuntime(s))
		assert.NoFileExists(t, path)
	})

	t.Run("moving the socket restarts at the new path", func(t *testing.T) {
		s, c := newTestCtlServer(t)
		oldPath := testCtlSocket(t)
		newPath := testCtlSocket(t)
		setCtlConfig(c, map[string]any{"socket": oldPath})
		require.NoError(t, s.reload(c, true))

		done := startCtl(t, s)
		waitFor(t, func() bool { return currentCtlRuntime(s) != nil })
		require.FileExists(t, oldPath)

		setCtlConfig(c, map[string]any{"socket": newPath})
		require.NoError(t, s.reload(c, false))
		requireCtlStopped(t, done)

		waitFor(t, func() bool { return currentCtlRuntime(s) != nil })
		assert.FileExists(t, newPath)
		assert.NoFileExists(t, oldPath, "the old socket should have been unlinked")

		s.Stop()
	})

	t.Run("an unchanged config leaves the listener alone", func(t *testing.T) {
		s, c := newTestCtlServer(t)
		setCtlConfig(c, map[string]any{"socket": testCtlSocket(t)})
		require.NoError(t, s.reload(c, true))

		startCtl(t, s)
		waitFor(t, func() bool { return currentCtlRuntime(s) != nil })
		before := currentCtlRuntime(s)

		require.NoError(t, s.reload(c, false))
		assert.Same(t, before, currentCtlRuntime(s), "the runtime should not have been replaced")

		s.Stop()
	})
}

func TestCtlServer_Start(t *testing.T) {
	t.Run("a command can be run over the socket", func(t *testing.T) {
		l := slog.New(slog.DiscardHandler)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		reg := diag.NewRegistry()
		s := &ctlServer{l: l, ctx: ctx, srv: diag.NewServer(l, reg)}
		c := config.NewC(l)

		path := testCtlSocket(t)
		setCtlConfig(c, map[string]any{"socket": path})
		require.NoError(t, s.reload(c, true))

		startCtl(t, s)
		waitFor(t, func() bool { return currentCtlRuntime(s) != nil })

		client, err := diag.Dial(path)
		require.NoError(t, err)
		defer client.Close()

		out := &testWriter{}
		status, err := client.Run([]string{"help"}, out)
		require.NoError(t, err)
		assert.Equal(t, diag.StatusOK, status)
		assert.Contains(t, out.String(), "Available commands:")

		s.Stop()
	})

	t.Run("Start is a no-op when ctl is disabled", func(t *testing.T) {
		s, c := newTestCtlServer(t)
		setCtlConfig(c, map[string]any{"enabled": false, "socket": testCtlSocket(t)})
		require.NoError(t, s.reload(c, true))

		s.Start()
		assert.Nil(t, currentCtlRuntime(s))
	})

	t.Run("Start is a no-op with no socket path for this platform", func(t *testing.T) {
		s, c := newTestCtlServer(t)
		setCtlConfig(c, map[string]any{"enabled": true, "socket": ""})
		require.NoError(t, s.reload(c, true))

		s.Start()
		assert.Nil(t, currentCtlRuntime(s))
	})

	t.Run("Start is a no-op after the context is cancelled", func(t *testing.T) {
		l := slog.New(slog.DiscardHandler)
		ctx, cancel := context.WithCancel(context.Background())
		s := &ctlServer{l: l, ctx: ctx, srv: diag.NewServer(l, diag.NewRegistry())}
		c := config.NewC(l)

		path := testCtlSocket(t)
		setCtlConfig(c, map[string]any{"socket": path})
		require.NoError(t, s.reload(c, true))
		cancel()

		s.Start()
		assert.Nil(t, currentCtlRuntime(s))
		assert.NoFileExists(t, path)
	})

	// A path nebula cannot bind must not stop it from running, and a SIGHUP with the same
	// config has to be able to retry once the problem is fixed.
	t.Run("a listen failure is survivable and retried on the next reload", func(t *testing.T) {
		s, c := newTestCtlServer(t)
		path := testCtlSocket(t)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
		require.NoError(t, os.WriteFile(path, []byte("in the way"), 0600))

		setCtlConfig(c, map[string]any{"socket": path})
		require.NoError(t, s.reload(c, true))

		s.Start()
		assert.Nil(t, currentCtlRuntime(s))

		s.runMu.Lock()
		cachedCfg := s.runCfg
		s.runMu.Unlock()
		assert.Nil(t, cachedCfg, "the cached config should be dropped so a reload retries")

		require.NoError(t, os.Remove(path))
		require.NoError(t, s.reload(c, false))
		waitFor(t, func() bool { return currentCtlRuntime(s) != nil })

		s.Stop()
	})

	t.Run("Stop is idempotent", func(t *testing.T) {
		s, c := newTestCtlServer(t)
		setCtlConfig(c, map[string]any{"socket": testCtlSocket(t)})
		require.NoError(t, s.reload(c, true))

		done := startCtl(t, s)
		waitFor(t, func() bool { return currentCtlRuntime(s) != nil })

		s.Stop()
		requireCtlStopped(t, done)
		assert.NotPanics(t, s.Stop)
	})
}

// testWriter collects command output.
type testWriter struct{ b []byte }

func (w *testWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func (w *testWriter) String() string { return string(w.b) }
