package wintun

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestResetLimiter(t *testing.T) {
	base := time.Unix(1000, 0)
	now := base
	lim := newResetLimiter(3, 10*time.Second, func() time.Time { return now })

	assert.True(t, lim.allow())
	now = now.Add(2 * time.Second)
	assert.True(t, lim.allow())
	now = now.Add(2 * time.Second)
	assert.True(t, lim.allow())

	// Denied up through window - 1ns; oldest slot expires at exact window.
	now = base.Add(10*time.Second - time.Nanosecond)
	assert.False(t, lim.allow())
	now = base.Add(10 * time.Second)
	assert.True(t, lim.allow())
	assert.False(t, lim.allow())

	// Invalid/disabled configs fail closed.
	for _, tc := range []struct {
		max    int
		window time.Duration
	}{{0, 10 * time.Second}, {-1, 10 * time.Second}, {3, 0}, {3, -time.Second}} {
		l := newResetLimiter(tc.max, tc.window, func() time.Time { return now })
		assert.False(t, l.allow())
	}

	def := newResetLimiter(1, time.Second, nil)
	assert.True(t, def.allow())
	assert.False(t, def.allow())
}
