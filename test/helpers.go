package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ShortTempDir returns a short private directory of the test's own, removed when the
// test ends. t.TempDir embeds the test name, which on darwin routinely pushes a unix
// socket path laid out under it past the 104 byte sun_path limit.
func ShortTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "la")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// Golden compares got with the file at path, or rewrites the file when update is set,
// which is what a test's -update flag asks for.
func Golden(t *testing.T, path, got string, update bool) {
	t.Helper()

	if update {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(got), 0644))
		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden file, run with -update")
	assert.Equal(t, string(want), got)
}
