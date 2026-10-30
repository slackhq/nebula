package nebula

import (
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

func TestMultiPortReplayWindow(t *testing.T) {
	l := test.NewLogger()
	tests := []struct {
		name       string
		configured int
		want       uint64
	}{
		{"default", ReplayWindow, ReplayWindow},
		{"larger", 1 << 16, 1 << 16},
		{"max", maxReplayWindow, maxReplayWindow},
		{"too small", 4096, ReplayWindow},
		{"too big", maxReplayWindow * 2, ReplayWindow},
		{"not a power of two", 50000, ReplayWindow},
		{"zero", 0, ReplayWindow},
		{"negative", -1, ReplayWindow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, multiPortReplayWindow(l, tt.configured))
		})
	}
}

func TestReplayWindowForTunnel(t *testing.T) {
	assert.Equal(t, uint64(1<<16), replayWindow(config.MultiPortConfig{ReplayWindow: 1 << 16}))
	// Every tunnel gets it, multiport or not
	assert.Equal(t, uint64(1<<16), replayWindow(config.MultiPortConfig{Rx: true, Tx: true, ReplayWindow: 1 << 16}))
	// Before a config is loaded
	assert.Equal(t, uint64(ReplayWindow), replayWindow(config.MultiPortConfig{}))
}
