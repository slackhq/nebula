package nebula

import (
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake"
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

func TestMultiportVia(t *testing.T) {
	from := ViaSender{UdpAddr: netip.MustParseAddrPort("1.2.3.4:4300")}
	peerTx := &handshake.Result{MultiportTx: true, MultiportBasePort: 4242}

	// We agreed to rx and the peer sends multiport, answer its base port
	assert.Equal(t, netip.MustParseAddrPort("1.2.3.4:4242"), multiportVia(from, config.MultiPortConfig{Rx: true}, peerTx).UdpAddr)
	// Without our rx the source port is the real one, a NAT may have rewritten it
	assert.Equal(t, from, multiportVia(from, config.MultiPortConfig{}, peerTx))
	// The peer does not send multiport
	assert.Equal(t, from, multiportVia(from, config.MultiPortConfig{Rx: true}, &handshake.Result{}))
	// Relayed handshakes have no underlay port
	relayed := ViaSender{IsRelayed: true}
	assert.Equal(t, relayed, multiportVia(relayed, config.MultiPortConfig{Rx: true}, peerTx))
}

func TestMultiportAgreed(t *testing.T) {
	tx, rx := multiportAgreed(config.MultiPortConfig{Tx: true, Rx: true}, &handshake.Result{MultiportRx: true})
	assert.True(t, tx)
	assert.False(t, rx)
	tx, rx = multiportAgreed(config.MultiPortConfig{Rx: true}, &handshake.Result{MultiportRx: true, MultiportTx: true})
	assert.False(t, tx)
	assert.True(t, rx)
}
