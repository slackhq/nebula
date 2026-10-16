package nebula

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lineWriter struct {
	lines []string
	err   error
}

func (w *lineWriter) WriteLine(s string) error {
	w.lines = append(w.lines, s)
	return w.err
}
func (w *lineWriter) Write(s string) error      { return w.WriteLine(s) }
func (w *lineWriter) WriteBytes(b []byte) error { return w.WriteLine(string(b)) }
func (w *lineWriter) GetWriter() io.Writer      { return io.Discard }

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

	// reload returns what the client was told. A reload that failed is a commands.Failure
	// to the surface, exit 1 over ssh, with the result line as its message; one that
	// merely needs a restart is not.
	reload := func(failed bool) []string {
		w := &lineWriter{}
		err := reloadCommand(l, c, w)
		if failed {
			var f *commands.Failure
			require.ErrorAs(t, err, &f)
			assert.Equal(t, w.lines[len(w.lines)-1], f.Msg)
		} else {
			require.NoError(t, err)
		}
		return w.lines
	}

	write("a: 2\nb: 1")
	assert.Equal(t, []string{"Reloading config", "Config reload complete"}, reload(false))

	fail = true
	write("a: 3\nb: 1")
	assert.Equal(t, []string{"Reloading config", "Config reload completed with errors, review the logs"}, reload(true))

	fail = false
	write("a: 3\nb: 2")
	assert.Equal(t, []string{"Reloading config", "Config reload was completed but requires a restart to fully apply, keys [b]"}, reload(false))

	write("a: [")
	lines := reload(true)
	require.Len(t, lines, 2)
	assert.Contains(t, lines[1], "Config reload failed, the new config did not load")
	assert.Contains(t, lines[1], dir, "names the config that did not load")
}

// A client that went away still gets the reload it asked for
func TestReloadCommandReloadsWhenTheClientIsGone(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte("a: 1"), 0o600))
	l := test.NewLogger()
	c := config.NewC(l)
	require.NoError(t, c.Load(dir))
	reloaded := false
	c.RegisterReloadCallback(func(*config.C, *config.Reload) { reloaded = true })

	gone := errors.New("client is gone")
	require.ErrorIs(t, reloadCommand(l, c, &lineWriter{err: gone}), gone)
	assert.True(t, reloaded)
}
