package nebula

import (
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/udp"
)

// multiPortSettings holds the reloadable multiport config. The interface and the handshake manager share one, the
// reload callback replaces the whole config at once so readers never see a mix of old and new fields.
type multiPortSettings struct {
	p atomic.Pointer[config.MultiPortConfig]
}

// Load returns the current config, the zero config (multiport off) if none was stored or s is nil.
func (s *multiPortSettings) Load() config.MultiPortConfig {
	if s == nil {
		return config.MultiPortConfig{}
	}
	if c := s.p.Load(); c != nil {
		return *c
	}
	return config.MultiPortConfig{}
}

// Store replaces the config and reports its tx ports, 0 when tx is off
func (s *multiPortSettings) Store(c config.MultiPortConfig) {
	s.p.Store(&c)
	metrics.GetOrRegisterGauge("multiport.tx_ports", nil).Update(int64(c.TxPorts))
}

// maxReplayWindow caps tun.multiport.replay_window, 128KB per tunnel
const maxReplayWindow = 1 << 20

// replayWindow returns the replay window length for a new tunnel, the default ReplayWindow until a config is loaded
func replayWindow(mpc config.MultiPortConfig) uint64 {
	return max(mpc.ReplayWindow, ReplayWindow)
}

// defaultReplayWindowMax is how far a tunnel's replay window may grow by default, it covered 8 routines at ~24 Gbps
const defaultReplayWindowMax = 1 << 16

// newTunnelConnectionState builds a tunnel's ConnectionState from its handshake result and the multiport config
func newTunnelConnectionState(r *handshake.Result, mpc config.MultiPortConfig) (*ConnectionState, error) {
	cs, err := newConnectionStateFromResult(r, replayWindow(mpc), mpc.EncryptQueues)
	if err != nil {
		return nil, err
	}
	cs.replayWindowMax = mpc.ReplayWindowMax
	return cs, nil
}

// multiPortReplayWindowMax validates tun.multiport.replay_window_max, a power of two from window to maxReplayWindow.
// Anything else falls back to window, which turns growth off.
func multiPortReplayWindowMax(l *slog.Logger, configured int, window uint64) uint64 {
	w := uint64(configured)
	if configured < 0 || w < window || w > maxReplayWindow || w&(w-1) != 0 {
		l.Warn("tun.multiport.replay_window_max must be a power of two from tun.multiport.replay_window to 1048576, not growing replay windows",
			"configured", configured, "replayWindow", window)
		return window
	}
	return w
}

// multiPortReplayWindow validates tun.multiport.replay_window, a power of two from ReplayWindow to maxReplayWindow.
// Anything else falls back to ReplayWindow.
func multiPortReplayWindow(l *slog.Logger, configured int) uint64 {
	w := uint64(configured)
	if configured < ReplayWindow || w > maxReplayWindow || w&(w-1) != 0 {
		l.Warn("tun.multiport.replay_window must be a power of two from 8192 to 1048576, using 8192",
			"configured", configured)
		return ReplayWindow
	}
	return w
}

// multiportConn returns the multiport send sockets for packets to hostinfo, nil when they are not sent multiport
func (f *Interface) multiportConn(hostinfo *HostInfo) *udp.MultiPortConn {
	if !hostinfo.multiportTx || !f.multiPort.Load().Tx {
		return nil
	}
	return f.udpMulti.Load()
}

// multiportSendPort returns the multiport send port for every segment of an inside packet of flow to hostinfo, 0 (the
// main listener) when it is not sent multiport. Segments of a superpacket share one 5-tuple, so one port.
func (f *Interface) multiportSendPort(hostinfo *HostInfo, flow *firewall.Packet) uint16 {
	if mp := f.multiportConn(hostinfo); mp != nil {
		return flow.UDPSendPort(mp.Ports())
	}
	return 0
}

// multiportWriter returns the socket queue q sends a packet to hostinfo from: the socket for flow's multiport send
// port, a random one when flow is nil so there is no flow to keep together, or the main listener when it is not sent
// multiport.
func (f *Interface) multiportWriter(hostinfo *HostInfo, q int, flow *firewall.Packet) udp.Conn {
	mp := f.multiportConn(hostinfo)
	if mp == nil {
		return f.writers[q]
	}
	port := udp.RandomSendPort(mp.Ports())
	if flow != nil {
		port = flow.UDPSendPort(mp.Ports())
	}
	return mp.Conn(port, q, f.writers[q])
}

// multiportAgreed returns whether we send to the peer of a handshake result multiport and whether it sends to us
// multiport. Each needs the sender to have tx and the receiver rx.
func multiportAgreed(mpc config.MultiPortConfig, r *handshake.Result) (tx, rx bool) {
	return mpc.Tx && r.MultiportRx, mpc.Rx && r.MultiportTx
}

// multiportVia aims via at the peer's multiport base port when the peer sends multiport and we agreed to receive it:
// its handshake may have come from any of its send ports, and responses go to the base port. Without our rx agreement
// the source port is the real one, possibly rewritten by a NAT on the way, so via is left alone.
func multiportVia(via ViaSender, mpc config.MultiPortConfig, r *handshake.Result) ViaSender {
	if !via.IsRelayed && mpc.Rx && r.MultiportTx && r.MultiportBasePort != via.UdpAddr.Port() {
		via.UdpAddr = netip.AddrPortFrom(via.UdpAddr.Addr(), r.MultiportBasePort)
	}
	return via
}

// multiPortLoader loads tun.multiport at startup and on every reload
type multiPortLoader struct {
	l        *slog.Logger
	settings *multiPortSettings
	// conn holds the send sockets once tx is first enabled, they are never replaced since the send path uses them
	// without locking
	conn *atomic.Pointer[udp.MultiPortConn]
	open func(l *slog.Logger, base udp.Settings, ports, queues int) (*udp.MultiPortConn, error)

	listen   netip.AddrPort
	queues   int
	routines int
}

func (m *multiPortLoader) load(c *config.C, r *config.Reload) {
	l := m.l
	// Build the whole config before storing it, readers load it without locking
	mpc := config.MultiPortConfig{
		Rx:           c.GetBool("tun.multiport.rx_enabled", false),
		ReplayWindow: multiPortReplayWindow(l, c.GetInt("tun.multiport.replay_window", ReplayWindow)),
	}
	mpc.ReplayWindowMax = multiPortReplayWindowMax(l,
		c.GetInt("tun.multiport.replay_window_max", int(max(defaultReplayWindowMax, mpc.ReplayWindow))), mpc.ReplayWindow)
	if c.GetBool("tun.multiport.parallel_encrypt", true) {
		mpc.EncryptQueues = m.routines
	}

	tx := c.GetBool("tun.multiport.tx_enabled", false)
	txPorts := c.GetInt("tun.multiport.tx_ports", 100)

	mp := m.conn.Load()
	if tx && mp == nil {
		var err error
		mp, err = m.open(l, udp.Settings{Listen: m.listen, Offloads: c.GetBool("listen.udp_offloads", true)}, txPorts, m.queues)
		if err != nil {
			// Keep running without multiport tx, but a reload reports it failed. Nil at startup, a no-op there.
			l.Error("Failed to open udp sockets for tun.multiport.tx_enabled", "error", err)
			r.Failed()
			mp = nil
			tx = false
		} else {
			m.conn.Store(mp)
		}
	} else if mp != nil && mp.Ports() != txPorts {
		// The sockets keep the port count they were opened with. A different tx_ports needs a restart, including one
		// changed by an earlier reload while tx was off.
		r.RestartRequiredIfChanged("tun.multiport.tx_ports")
		r.RestartRequired()
	}

	if tx {
		mpc.Tx = true
		mpc.TxBasePort = m.listen.Port()
		mpc.TxPorts = mp.Ports()
		mpc.TxHandshake = c.GetBool("tun.multiport.tx_handshake", false)
		mpc.TxHandshakeDelay = int64(c.GetInt("tun.multiport.tx_handshake_delay", 2))
		mp.ReloadConfig(c, r)
	}
	m.settings.Store(mpc)

	l.Info("Multiport configured", "multiPort", mpc)
}
