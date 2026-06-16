package nebula

import (
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/require"
)

// TestPrometheusStatsReentrant guards against a regression where starting the
// prometheus stats listener more than once in the same process panics with
// `pattern "/metrics" conflicts`. This happens whenever an embedder tears down
// and re-runs Main()/Control.Start() in the same process — for example on a
// config change that requires a restart. Each start must get its own HTTP mux.
func TestPrometheusStatsReentrant(t *testing.T) {
	l := test.NewLogger()

	makeStartFn := func() func() {
		c := config.NewC(l)
		// listen: 127.0.0.1:0 gives each instance its own ephemeral port, so a
		// successful second start does not collide on the address — isolating
		// the handler-registration bug from any bind conflict.
		require.NoError(t, c.LoadString("stats:\n  listen: 127.0.0.1:0\n  path: /metrics\n"))
		startFn, err := startPrometheusStats(l, time.Second, c, "test", false)
		require.NoError(t, err)
		require.NotNil(t, startFn)
		return startFn
	}

	first := makeStartFn()
	second := makeStartFn()

	// A startFn that registers its handler successfully then blocks serving, so
	// its deferred recover() never fires. A startFn that panics on a duplicate
	// registration unwinds immediately and sends the recovered value. We only
	// hear from the broken path.
	panics := make(chan any, 2)
	run := func(fn func()) {
		go func() {
			defer func() { panics <- recover() }()
			fn()
		}()
	}
	run(first)
	run(second)

	select {
	case p := <-panics:
		if p != nil {
			t.Fatalf("startPrometheusStats panicked when started twice in one process: %v", p)
		}
	case <-time.After(time.Second):
		// No panic inside the window: both instances registered their handlers
		// on independent muxes and are serving. This is the fixed behavior.
	}
}
