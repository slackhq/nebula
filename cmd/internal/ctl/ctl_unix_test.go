//go:build !windows

package ctl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slackhq/nebula/localapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveSocketDiagnosesAnOverlongOverride: the CLI applies the daemon's own rule to
// the override, so it says what the daemon's log says rather than dialing a path the
// kernel would truncate and reporting the generic failure. The rule is sun_path's, which
// a named pipe does not have, so this is a unix test.
func TestResolveSocketDiagnosesAnOverlongOverride(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	long := "/" + strings.Repeat("x", 120)
	require.NoError(t, os.WriteFile(cfg, []byte("local_api:\n  control:\n    socket: "+long+"\n"), 0600))

	_, _, _, err := resolveSocket("", cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, "too long for this platform")
	assert.ErrorContains(t, err, localapi.CtlSocketKey)
}
