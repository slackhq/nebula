package nebula

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWakeDetector(t *testing.T) {
	delta := time.Duration(0)
	ok := true
	w := &wakeDetector{read: func() (time.Duration, bool) { return delta, ok }}

	// The first sample primes the baseline and never reports a wake, even with a pre-existing spread
	delta = 3 * time.Hour
	slept, sok := w.Sample()
	assert.True(t, sok)
	assert.Equal(t, time.Duration(0), slept)

	// A stable spread means the machine never slept
	slept, sok = w.Sample()
	assert.True(t, sok)
	assert.Equal(t, time.Duration(0), slept)

	// The spread grows by exactly the time spent suspended
	delta += 42 * time.Second
	slept, sok = w.Sample()
	assert.True(t, sok)
	assert.Equal(t, 42*time.Second, slept)

	// A wake is reported once, then the baseline moves with it
	slept, sok = w.Sample()
	assert.True(t, sok)
	assert.Equal(t, time.Duration(0), slept)

	// Negative jitter from the non-atomic clock pair reads clamps to zero
	delta -= time.Microsecond
	slept, sok = w.Sample()
	assert.True(t, sok)
	assert.Equal(t, time.Duration(0), slept)

	// Consecutive suspends both report; the clamped jitter moved the baseline so it is not double-counted
	delta += time.Minute
	slept, _ = w.Sample()
	assert.Equal(t, time.Minute, slept)
	delta += time.Hour
	slept, _ = w.Sample()
	assert.Equal(t, time.Hour, slept)

	// An unsupported platform read reports not-ok
	ok = false
	_, sok = w.Sample()
	assert.False(t, sok)
}

// TestWakeDetectorPlatformClock smoke tests the real clock pair: two samples close together must not report a
// wake on a machine that isn't suspending mid-test.
func TestWakeDetectorPlatformClock(t *testing.T) {
	w := newWakeDetector()
	if _, ok := w.Sample(); !ok {
		t.Skip("platform has no suspend clock pair")
	}
	slept, ok := w.Sample()
	assert.True(t, ok)
	assert.Less(t, slept, time.Second)
}
