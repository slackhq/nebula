package nebula

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReloadCommandReportsTheResult(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(body), 0o600))
	}
	write("a: 1\nb: 1")
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.Load(dir))
	fail := false
	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		r.RestartRequiredIfChanged("b")
		if fail {
			r.Failed()
		}
	})

	// reload reports what happened. A reload that failed is a refusal, exit 1 over ssh;
	// one that merely needs a restart is not.
	reload := func(failed bool) string {
		res := runReload(l, c)
		assert.Equal(t, !failed, res.OK)
		return res.Reason
	}

	write("a: 2\nb: 1")
	assert.Equal(t, "Config reload complete", reload(false))

	fail = true
	write("a: 3\nb: 1")
	assert.Equal(t, "Config reload completed with errors, review the logs", reload(true))

	fail = false
	write("a: 3\nb: 2")
	assert.Equal(t, "Config reload was completed but requires a restart to fully apply, keys [b]", reload(false))

	write("a: [")
	reason := reload(true)
	assert.Contains(t, reason, "Config reload failed, the new config did not load")
	assert.Contains(t, reason, dir, "names the config that did not load")
}
