package nebula

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestMultiPortReplayWindowMax(t *testing.T) {
	l := test.NewLogger()
	assert.Equal(t, uint64(1<<16), multiPortReplayWindowMax(l, 1<<16, ReplayWindow))
	assert.Equal(t, uint64(ReplayWindow), multiPortReplayWindowMax(l, ReplayWindow, ReplayWindow))
	// Below the starting window, not a power of two, too big, negative: no growth
	assert.Equal(t, uint64(1<<16), multiPortReplayWindowMax(l, 1<<15, 1<<16))
	assert.Equal(t, uint64(ReplayWindow), multiPortReplayWindowMax(l, 50000, ReplayWindow))
	assert.Equal(t, uint64(ReplayWindow), multiPortReplayWindowMax(l, maxReplayWindow*2, ReplayWindow))
	assert.Equal(t, uint64(ReplayWindow), multiPortReplayWindowMax(l, -1, ReplayWindow))
}

func newTestMultiPortLoader(t *testing.T, open func(*slog.Logger, udp.Settings, int, int) (*udp.MultiPortConn, error)) (*multiPortLoader, *atomic.Pointer[udp.MultiPortConn]) {
	conn := &atomic.Pointer[udp.MultiPortConn]{}
	return &multiPortLoader{
		l: test.NewLogger(), settings: &multiPortSettings{}, conn: conn, open: open,
		listen: netip.MustParseAddrPort("127.0.0.1:4242"), queues: 2, routines: 8,
	}, conn
}

func TestMultiPortLoaderDefaults(t *testing.T) {
	m, _ := newTestMultiPortLoader(t, nil)
	c := config.NewC(test.NewLogger())
	m.load(c, nil)
	mpc := m.settings.Load()
	assert.False(t, mpc.Tx)
	assert.False(t, mpc.Rx)
	assert.Equal(t, uint64(ReplayWindow), mpc.ReplayWindow)
	assert.Equal(t, uint64(defaultReplayWindowMax), mpc.ReplayWindowMax)
	assert.Equal(t, 8, mpc.EncryptQueues)

	// A replay_window above the default max raises the max with it instead of turning growth off
	require.NoError(t, c.LoadString("tun:\n  multiport:\n    replay_window: 131072\n    parallel_encrypt: false\n"))
	m.load(c, nil)
	mpc = m.settings.Load()
	assert.Equal(t, uint64(131072), mpc.ReplayWindow)
	assert.Equal(t, uint64(131072), mpc.ReplayWindowMax)
	assert.Zero(t, mpc.EncryptQueues)
}

func TestMultiPortLoaderOpenFails(t *testing.T) {
	m, conn := newTestMultiPortLoader(t, func(*slog.Logger, udp.Settings, int, int) (*udp.MultiPortConn, error) {
		return nil, errors.New("port in use")
	})
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString("tun:\n  multiport:\n    tx_enabled: true\n    rx_enabled: true\n"))
	c.RegisterReloadCallback(m.load)

	// Startup keeps running without tx
	m.load(c, nil)
	assert.False(t, m.settings.Load().Tx)
	assert.True(t, m.settings.Load().Rx)
	assert.Nil(t, conn.Load())

	// A reload tries again, still runs without tx, and reports it failed
	res := c.ReloadConfigString("tun:\n  multiport:\n    tx_enabled: true\n    rx_enabled: true\n")
	assert.True(t, res.Failed)
	assert.False(t, m.settings.Load().Tx)
}

func TestMultiPortLoaderTxPortsRestart(t *testing.T) {
	// Real sockets on consecutive ports after a free one
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	base := probe.LocalAddr().(*net.UDPAddr).AddrPort()
	require.NoError(t, probe.Close())

	m, conn := newTestMultiPortLoader(t, udp.NewMultiPortConn)
	m.listen = base
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString("tun:\n  multiport:\n    tx_enabled: true\n    tx_ports: 3\n"))
	c.RegisterReloadCallback(m.load)
	m.load(c, nil)
	if conn.Load() == nil {
		t.Skipf("unable to bind consecutive ports after %d", base.Port())
	}
	defer conn.Load().Close()
	assert.True(t, m.settings.Load().Tx)
	assert.Equal(t, 3, m.settings.Load().TxPorts)

	// Changing tx_ports while tx is off still needs a restart, the sockets keep 3 ports
	res := c.ReloadConfigString("tun:\n  multiport:\n    tx_enabled: false\n    tx_ports: 4\n")
	assert.True(t, res.RestartRequired)
	assert.Contains(t, res.RestartKeys, "tun.multiport.tx_ports")
	assert.False(t, m.settings.Load().Tx)

	// Turning tx back on keeps the sockets and their 3 ports, and still says to restart
	res = c.ReloadConfigString("tun:\n  multiport:\n    tx_enabled: true\n    tx_ports: 4\n")
	assert.True(t, res.RestartRequired)
	assert.Equal(t, 3, m.settings.Load().TxPorts)
}
