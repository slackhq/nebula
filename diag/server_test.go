//go:build !windows

package diag

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSocketPath returns a short socket path. t.TempDir on darwin lives under
// /var/folders/... and readily exceeds the 104 byte sun_path limit, which fails as a bare
// "invalid argument" a long way from the cause.
func testSocketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "nebctl")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "sub", "ctl.sock")
	require.LessOrEqual(t, len(path), maxSocketPath, "test socket path is too long for sun_path")
	return path
}

func newTestServer(t *testing.T) (*Registry, string) {
	t.Helper()

	reg := NewRegistry()
	path := testSocketPath(t)

	ln, err := Listen(path)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	srv := NewServer(slog.New(slog.DiscardHandler), reg)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, srv.Serve(ctx, ln))
	}()

	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	return reg, path
}

func run(t *testing.T, path string, args ...string) (string, int, error) {
	t.Helper()

	c, err := Dial(path)
	require.NoError(t, err)
	defer c.Close()

	out := &bytes.Buffer{}
	status, err := c.Run(args, out)
	return out.String(), status, err
}

func TestServeConn(t *testing.T) {
	t.Run("a command runs and its output comes back", func(t *testing.T) {
		reg, path := newTestServer(t)
		reg.RegisterCommand(&Command{
			Name:             "version",
			ShortDescription: "prints a version",
			Callback: func(fs any, a []string, w StringWriter) error {
				return w.WriteLine("1.2.3")
			},
		})

		out, status, err := run(t, path, "version")
		require.NoError(t, err)
		assert.Equal(t, StatusOK, status)
		assert.Equal(t, "1.2.3\n", out)
	})

	t.Run("no args gets the command list", func(t *testing.T) {
		_, path := newTestServer(t)

		out, status, err := run(t, path)
		require.NoError(t, err)
		assert.Equal(t, StatusOK, status)
		assert.Contains(t, out, "Available commands:")
	})

	t.Run("an unknown command exits 127", func(t *testing.T) {
		_, path := newTestServer(t)

		out, status, err := run(t, path, "nope")
		require.NoError(t, err)
		assert.Equal(t, StatusUnknownCommand, status)
		assert.Contains(t, out, "Did not understand: nope")
	})

	t.Run("a bad flag exits 2", func(t *testing.T) {
		reg, path := newTestServer(t)
		var seen any
		reg.RegisterCommand(testCommand("do-thing", &seen, nil))

		out, status, err := run(t, path, "do-thing", "-nope")
		require.NoError(t, err)
		assert.Equal(t, StatusUsage, status)
		assert.Contains(t, out, "flag provided but not defined")
	})

	t.Run("a callback error exits 1 and reports why", func(t *testing.T) {
		reg, path := newTestServer(t)
		reg.RegisterCommand(&Command{
			Name:             "explode",
			ShortDescription: "fails",
			Callback: func(fs any, a []string, w StringWriter) error {
				return errors.New("boom")
			},
		})

		_, status, err := run(t, path, "explode")
		require.Error(t, err)
		assert.Equal(t, StatusError, status)
		assert.Contains(t, err.Error(), "boom")
	})

	t.Run("output larger than the buffer arrives intact", func(t *testing.T) {
		reg, path := newTestServer(t)
		want := bytes.Repeat([]byte("x"), outputBuffer*3+7)
		reg.RegisterCommand(&Command{
			Name:             "big",
			ShortDescription: "writes a lot",
			Callback: func(fs any, a []string, w StringWriter) error {
				return w.WriteBytes(want)
			},
		})

		out, status, err := run(t, path, "big")
		require.NoError(t, err)
		assert.Equal(t, StatusOK, status)
		assert.Equal(t, string(want), out)
	})

	t.Run("concurrent clients are all served", func(t *testing.T) {
		reg, path := newTestServer(t)
		reg.RegisterCommand(&Command{
			Name:             "slow",
			ShortDescription: "takes a moment",
			Callback: func(fs any, a []string, w StringWriter) error {
				time.Sleep(10 * time.Millisecond)
				return w.WriteLine("done")
			},
		})

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				out, status, err := run(t, path, "slow")
				assert.NoError(t, err)
				assert.Equal(t, StatusOK, status)
				assert.Equal(t, "done\n", out)
			}()
		}
		wg.Wait()
	})

	t.Run("a client that hangs up mid command does not take the server down", func(t *testing.T) {
		reg, path := newTestServer(t)
		reg.RegisterCommand(&Command{
			Name:             "version",
			ShortDescription: "prints a version",
			Callback: func(fs any, a []string, w StringWriter) error {
				return w.WriteLine("1.2.3")
			},
		})

		c, err := Dial(path)
		require.NoError(t, err)
		require.NoError(t, writeRequest(c.conn, []string{"version"}))
		require.NoError(t, c.Close())

		// The next client still gets served.
		out, status, err := run(t, path, "version")
		require.NoError(t, err)
		assert.Equal(t, StatusOK, status)
		assert.Equal(t, "1.2.3\n", out)
	})
}

func TestListenSocket(t *testing.T) {
	t.Run("the socket is 0600 inside a 0700 directory", func(t *testing.T) {
		path := testSocketPath(t)
		ln, err := Listen(path)
		require.NoError(t, err)
		defer ln.Close()

		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(), "socket mode")

		di, err := os.Stat(filepath.Dir(path))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0700), di.Mode().Perm(), "socket directory mode")
	})

	t.Run("the socket is unlinked when the listener closes", func(t *testing.T) {
		path := testSocketPath(t)
		ln, err := Listen(path)
		require.NoError(t, err)
		require.NoError(t, ln.Close())

		_, err = os.Stat(path)
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	// A crashed nebula leaves its socket behind, and the next one has to be able to start.
	t.Run("a socket left behind by a dead nebula is replaced", func(t *testing.T) {
		path := testSocketPath(t)
		ln, err := Listen(path)
		require.NoError(t, err)

		// Close the listener without unlinking, the way a killed process leaves things.
		unix, ok := ln.(*net.UnixListener)
		require.True(t, ok)
		unix.SetUnlinkOnClose(false)
		require.NoError(t, ln.Close())
		require.FileExists(t, path)

		ln2, err := Listen(path)
		require.NoError(t, err)
		assert.NoError(t, ln2.Close())
	})

	// Silently stealing it would break the nebula that got there first.
	t.Run("a socket another nebula is serving is refused", func(t *testing.T) {
		_, path := newTestServer(t)

		_, err := Listen(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already being served")
	})

	t.Run("a path that is not a socket is refused rather than removed", func(t *testing.T) {
		path := testSocketPath(t)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
		require.NoError(t, os.WriteFile(path, []byte("precious"), 0600))

		_, err := Listen(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a socket")
		assert.FileExists(t, path, "the file must not have been removed")
	})

	t.Run("a path too long for sun_path says so", func(t *testing.T) {
		_, err := Listen("/tmp/" + fmt.Sprintf("%0*d", maxSocketPath, 0) + "/ctl.sock")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "the maximum is")
	})
}
