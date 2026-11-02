package nebula

import (
	"log/slog"
	"sync/atomic"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
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

func (s *multiPortSettings) Store(c config.MultiPortConfig) {
	s.p.Store(&c)
}

// maxReplayWindow caps tun.multiport.replay_window, 128KB per tunnel
const maxReplayWindow = 1 << 20

// replayWindow returns the replay window length for a new tunnel, the default ReplayWindow until a config is loaded
func replayWindow(mpc config.MultiPortConfig) uint64 {
	return max(mpc.ReplayWindow, ReplayWindow)
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
