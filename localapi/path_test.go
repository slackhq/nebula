//go:build !windows

package localapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultSocketPathIsStable is what makes the endpoint work with no configuration:
// the daemon and the CLI derive the same path from the same config, independently.
func TestDefaultSocketPathIsStable(t *testing.T) {
	privateBase(t)

	a, err := DefaultSocketPath("/etc/nebula/config.yml")
	require.NoError(t, err)

	b, err := DefaultSocketPath("/etc/nebula/config.yml")
	require.NoError(t, err)

	assert.Equal(t, a, b)
	assert.True(t, strings.HasSuffix(a, SocketExt))
}

// TestDefaultSocketPathSeparatesInstances: two nebulas on one host must not collide.
func TestDefaultSocketPathSeparatesInstances(t *testing.T) {
	privateBase(t)

	a, err := DefaultSocketPath("/etc/nebula/one.yml")
	require.NoError(t, err)
	b, err := DefaultSocketPath("/etc/nebula/two.yml")
	require.NoError(t, err)

	assert.NotEqual(t, a, b)
}

func TestDefaultSocketPathFitsSunPath(t *testing.T) {
	privateBase(t)

	p, err := DefaultSocketPath(strings.Repeat("/some-quite-long-directory-name", 8) + "/config.yml")
	require.NoError(t, err)
	assert.LessOrEqual(t, len(p), sunPathMax)
}

type fakeConfig map[string]string

func (f fakeConfig) GetString(k, d string) string {
	if v, ok := f[k]; ok {
		return v
	}
	return d
}

func TestSocketPathFromConfigHonoursOverride(t *testing.T) {
	p, err := SocketPathFromConfig(fakeConfig{CtlSocketKey: "/tmp/custom.sock"}, "/etc/nebula/config.yml")
	require.NoError(t, err)
	assert.Equal(t, "/tmp/custom.sock", p)
}

// TestSocketPathFromConfigResolvesRelativeOverride: the daemon and the CLI are started
// from different directories, so a relative override must mean the same socket to both.
// It is taken from the config's directory, and the working directory plays no part.
func TestSocketPathFromConfigResolvesRelativeOverride(t *testing.T) {
	// Short names: t.TempDir bakes the test name in, which on darwin pushes the resolved
	// socket past sun_path and fails for the wrong reason.
	base := privateBase(t)
	cfg := filepath.Join(base, "config.yml")
	require.NoError(t, os.WriteFile(cfg, nil, 0600))
	want := filepath.Join(base, "run", "ctl.sock")

	// From the config's own directory.
	t.Chdir(base)
	p, err := SocketPathFromConfig(fakeConfig{CtlSocketKey: "run/ctl.sock"}, cfg)
	require.NoError(t, err)
	assert.Equal(t, want, p)

	// From somewhere else entirely, with the config named relatively too.
	elsewhere := test.ShortTempDir(t)
	t.Chdir(elsewhere)
	p, err = SocketPathFromConfig(fakeConfig{CtlSocketKey: "run/ctl.sock"}, cfg)
	require.NoError(t, err)
	assert.Equal(t, want, p)

	t.Chdir(base)
	p, err = SocketPathFromConfig(fakeConfig{CtlSocketKey: "./run/../run/ctl.sock"}, "config.yml")
	require.NoError(t, err)
	assert.Equal(t, want, p)

	// A config directory is its own base.
	p, err = SocketPathFromConfig(fakeConfig{CtlSocketKey: "run/ctl.sock"}, base)
	require.NoError(t, err)
	assert.Equal(t, want, p)

	// A config that does not exist yet is taken to be a file.
	p, err = SocketPathFromConfig(fakeConfig{CtlSocketKey: "run/ctl.sock"}, filepath.Join(base, "missing", "config.yml"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "missing", "run", "ctl.sock"), p)
}

func TestSocketPathFromConfigFallsBackToDerived(t *testing.T) {
	privateBase(t)

	want, err := DefaultSocketPath("/etc/nebula/config.yml")
	require.NoError(t, err)

	got, err := SocketPathFromConfig(fakeConfig{}, "/etc/nebula/config.yml")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSocketPathFromConfigRejectsOverlongOverride(t *testing.T) {
	_, err := SocketPathFromConfig(fakeConfig{CtlSocketKey: "/" + strings.Repeat("x", sunPathMax)}, "/etc/nebula/config.yml")
	assert.ErrorContains(t, err, "too long for this platform")
}

// TestDefaultSocketPathFallsThrough covers the daemon landing in a later candidate
// directory because the first one made the path too long. The CLI runs the same
// derivation, so it lands there too, without looking anywhere.
func TestDefaultSocketPathFallsThrough(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root's only candidate is /var/run/nebula, which this test should not touch")
	}

	base := privateBase(t)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(base, strings.Repeat("x", maxSocketPath)))

	cfg := filepath.Join(base, "config.yml")
	p, err := DefaultSocketPath(cfg)
	require.NoError(t, err)
	require.NotEqual(t, candidateDirs()[0], filepath.Dir(p), "the first candidate is too long, so the daemon must fall through")
	require.Equal(t, base, filepath.Dir(filepath.Dir(p)), "the fallback is the per user directory under $TMPDIR")

	_, stop := serveAt(t, p)
	defer stop()

	again, err := DefaultSocketPath(cfg)
	require.NoError(t, err)
	assert.Equal(t, p, again, "the client's derivation is the daemon's")
	_, err = (&Client{Path: p}).Describe()
	require.NoError(t, err)
}

// TestDefaultSocketPathFollowsSymlinks: the daemon started with the real path and an
// operator naming the config through a symlink are talking about the same config, so
// they must land on the same socket.
func TestDefaultSocketPathFollowsSymlinks(t *testing.T) {
	base := privateBase(t)
	real := filepath.Join(base, "config.yml")
	require.NoError(t, os.WriteFile(real, []byte("{}\n"), 0644))
	link := filepath.Join(base, "link.yml")
	require.NoError(t, os.Symlink(real, link))

	a, err := DefaultSocketPath(real)
	require.NoError(t, err)
	b, err := DefaultSocketPath(link)
	require.NoError(t, err)
	assert.Equal(t, a, b)

	// Relative spellings resolve too.
	t.Chdir(base)
	c, err := DefaultSocketPath("link.yml")
	require.NoError(t, err)
	assert.Equal(t, a, c)
}
