package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPathInDir(t *testing.T) {
	t.Run("prefers config.yaml when both exist", func(t *testing.T) {
		dir := t.TempDir()
		yaml := filepath.Join(dir, "config.yaml")
		yml := filepath.Join(dir, "config.yml")
		require.NoError(t, os.WriteFile(yaml, []byte("a: 1"), 0644))
		require.NoError(t, os.WriteFile(yml, []byte("a: 2"), 0644))

		got, err := defaultPathInDir(dir)
		require.NoError(t, err)
		assert.Equal(t, yaml, got)
	})

	t.Run("returns config.yaml when only it exists", func(t *testing.T) {
		dir := t.TempDir()
		yaml := filepath.Join(dir, "config.yaml")
		require.NoError(t, os.WriteFile(yaml, []byte("a: 1"), 0644))

		got, err := defaultPathInDir(dir)
		require.NoError(t, err)
		assert.Equal(t, yaml, got)
	})

	t.Run("falls back to config.yml when only it exists", func(t *testing.T) {
		dir := t.TempDir()
		yml := filepath.Join(dir, "config.yml")
		require.NoError(t, os.WriteFile(yml, []byte("a: 1"), 0644))

		got, err := defaultPathInDir(dir)
		require.NoError(t, err)
		assert.Equal(t, yml, got)
	})

	t.Run("errors when neither exists and names both paths", func(t *testing.T) {
		dir := t.TempDir()
		got, err := defaultPathInDir(dir)
		assert.Empty(t, got)
		require.Error(t, err)
		assert.Contains(t, err.Error(), filepath.Join(dir, "config.yaml"))
		assert.Contains(t, err.Error(), filepath.Join(dir, "config.yml"))
	})
}

func TestDefaultPath(t *testing.T) {
	got, err := DefaultPath()
	if err != nil {
		ex, exErr := os.Executable()
		require.NoError(t, exErr)
		assert.Contains(t, err.Error(), filepath.Dir(ex))
		return
	}
	ex, err := os.Executable()
	require.NoError(t, err)
	assert.Equal(t, filepath.Dir(ex), filepath.Dir(got))
	assert.Contains(t, []string{"config.yaml", "config.yml"}, filepath.Base(got))
}
