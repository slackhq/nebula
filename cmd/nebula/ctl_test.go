package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/slackhq/nebula/diag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The daemon parses the command's own flags, so this side must consume its own and forward
// everything from the command name onwards untouched.
func TestCtlSocketPath(t *testing.T) {
	t.Run("a config naming a socket is used", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yml")
		require.NoError(t, os.WriteFile(path, []byte("ctl:\n  socket: /run/somewhere/ctl.sock\n"), 0600))

		assert.Equal(t, "/run/somewhere/ctl.sock", ctlSocketPath(path))
	})

	t.Run("a config without a ctl block falls back to the platform default", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yml")
		require.NoError(t, os.WriteFile(path, []byte("pki:\n  ca: /dev/null\n"), 0600))

		assert.Equal(t, diag.DefaultSocketPath(), ctlSocketPath(path))
	})

	// A packaged install keeps its config somewhere config.DefaultPath will never look, so a
	// config we cannot read is the ordinary case and must not be fatal.
	t.Run("an unreadable config falls back to the platform default", func(t *testing.T) {
		assert.Equal(t, diag.DefaultSocketPath(), ctlSocketPath(filepath.Join(t.TempDir(), "nope.yml")))
	})
}

func TestCtlDialError(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		wants string
	}{
		{"missing socket names the path and what to check", fs.ErrNotExist, "no control socket at /x/ctl.sock. Is nebula running?"},
		{"a stale socket is called stale", syscall.ECONNREFUSED, "found a stale socket at /x/ctl.sock"},
		{"permission denied suggests the right user", fs.ErrPermission, "must run as the user nebula runs as"},
		{"an unsupported platform says so", diag.ErrNotSupported, "not supported on this platform"},
		{"anything else is reported verbatim", errors.New("something else"), "something else"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, ctlDialError("/x/ctl.sock", tt.err), tt.wants)
		})
	}

	t.Run("a wrapped syscall error is still recognised", func(t *testing.T) {
		err := &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}
		assert.Contains(t, ctlDialError("/x/ctl.sock", err), "stale socket")
	})
}

func TestCtlCommandName(t *testing.T) {
	assert.Equal(t, "print-cert", ctlCommandName([]string{"print-cert", "-json"}))
	assert.Equal(t, "the command", ctlCommandName(nil))
}
