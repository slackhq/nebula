package test

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Update is the -update flag: Golden rewrites its file instead of comparing against it.
var Update = flag.Bool("update", false, "rewrite golden files instead of comparing against them")

// Golden compares got with the file at path, or rewrites the file when -update is set.
func Golden(t *testing.T, path, got string) {
	t.Helper()

	if *Update {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(got), 0644))
		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden file, run with -update")
	assert.Equal(t, string(want), got)
}
