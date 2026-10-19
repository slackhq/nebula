//go:build !windows

package localapi

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeConfig map[string]string

func (f fakeConfig) GetString(k, d string) string {
	if v, ok := f[k]; ok {
		return v
	}
	return d
}

// TestSocketPathFromConfigUsesTheDefault is what makes the endpoint work with no
// configuration: the daemon and the CLI both land on the one fixed path.
func TestSocketPathFromConfigUsesTheDefault(t *testing.T) {
	p, err := SocketPathFromConfig(fakeConfig{})
	require.NoError(t, err)
	assert.Equal(t, "/var/run/nebula/ctl.sock", p)
	assert.Equal(t, DefaultSocketPath(), p)
}

func TestSocketPathFromConfigHonoursOverride(t *testing.T) {
	p, err := SocketPathFromConfig(fakeConfig{CtlSocketKey: "/tmp/custom.sock"})
	require.NoError(t, err)
	assert.Equal(t, "/tmp/custom.sock", p, "the path is used as given")
}

// TestSocketPathFromConfigRefusesARelativeOverride: the daemon and the CLI are started
// from different directories, so a relative path would name two sockets from one config.
// It is refused rather than resolved against anything.
func TestSocketPathFromConfigRefusesARelativeOverride(t *testing.T) {
	for _, rel := range []string{"run/ctl.sock", "./ctl.sock", "ctl.sock", "../ctl.sock"} {
		_, err := SocketPathFromConfig(fakeConfig{CtlSocketKey: rel})
		require.Error(t, err, rel)
		require.ErrorContains(t, err, "must be an absolute path", rel)
		assert.ErrorContains(t, err, CtlSocketKey, rel)
	}
}

func TestSocketPathFromConfigRejectsOverlongOverride(t *testing.T) {
	_, err := SocketPathFromConfig(fakeConfig{CtlSocketKey: "/" + strings.Repeat("x", sunPathMax)})
	assert.ErrorContains(t, err, "too long for this platform")
}
