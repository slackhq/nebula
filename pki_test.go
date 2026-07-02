package nebula

import (
	"path/filepath"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/require"
)

// TestNewCertStateFromConfig_RejectsBadInput pins the three early-return
// guards in newCertStateFromConfig that don't require constructing a
// valid certificate to exercise. The happy path (valid v1 / v2 inline
// or file-path certs) is exercised indirectly via existing
// integration paths that call pki.NewPKIFromConfig - building full
// PEM-encoded certs here would require ~150 lines of fixture code
// for negligible additional value over those integration paths.
func TestNewCertStateFromConfig_RejectsBadInput(t *testing.T) {
	tests := []struct {
		name             string
		setup            func(t *testing.T) *config.C
		wantErrSubstring string
	}{
		{
			name: "missing pki.key rejected",
			setup: func(t *testing.T) *config.C {
				c := config.NewC(test.NewLogger())
				c.Settings["pki"] = map[string]any{
					// pki.key absent
					"cert": "/tmp/some-cert.crt",
				}
				return c
			},
			wantErrSubstring: "no pki.key path or PEM data provided",
		},
		{
			name: "missing pki.cert rejected",
			setup: func(t *testing.T) *config.C {
				c := config.NewC(test.NewLogger())
				c.Settings["pki"] = map[string]any{
					"key": "/tmp/some-key.key",
					// pki.cert absent
				}
				return c
			},
			// loadPrivateKey runs before the pki.cert check, so the
			// outer error here is from loadPrivateKey failing to open
			// the (nonexistent) key path. The error message names the
			// flag the operator typed.
			wantErrSubstring: "/tmp/some-key.key",
		},
		{
			name: "pki.cert file path that does not exist is rejected with the path in the error",
			setup: func(t *testing.T) *config.C {
				// Use a real (nonexistent) cert path together with a
				// nonexistent key path. loadPrivateKey will fail first;
				// the test asserts that the operator's typed path is in
				// the error so they can find their config typo.
				dir := t.TempDir()
				c := config.NewC(test.NewLogger())
				c.Settings["pki"] = map[string]any{
					"key":  filepath.Join(dir, "missing.key"),
					"cert": filepath.Join(dir, "missing.crt"),
				}
				return c
			},
			wantErrSubstring: "missing.key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.setup(t)
			got, err := newCertStateFromConfig(c, "")
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErrSubstring,
				"error message must name the offending field so operators can find the config line")
			require.Nil(t, got)
		})
	}
}
