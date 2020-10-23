package nebula

import (
	"sync/atomic"

	"github.com/flynn/noise"
	"go.uber.org/zap"
)

func (f *Interface) consumeInsidePacket(packet []byte, fwPacket *FirewallPacket, nb, out []byte) {
	err := newPacket(packet, false, fwPacket)
	if err != nil {
		l.Debug(
			"failed to validate outbound packet",
			zap.Error(err),
			zap.Any("packet", packet),
		)
		return
	}

	// Ignore local broadcast packets
	if f.dropLocalBroadcast && fwPacket.RemoteIP == f.localBroadcast {
		return
	}

	// Ignore packets from self to self
	if fwPacket.RemoteIP == f.lightHouse.myIp {
		return
	}

	// Ignore broadcast packets
	if f.dropMulticast && isMulticast(fwPacket.RemoteIP) {
		return
	}

	hostinfo := f.getOrHandshake(fwPacket.RemoteIP)
	if hostinfo == nil {
		l.Debug(
			"dropping outbound packet, vpnIp not in our CIDR or in unsafe routes",
			zap.Uint32("vpnIp", uint32(IntIp(fwPacket.RemoteIP))),
			zap.Any("fwPacket", fwPacket),
		)
		return
	}
	hostinfo.Lock()
	defer hostinfo.Unlock()
	ci := hostinfo.ConnectionState

	ci.mx.RLock()
	ready := ci.ready
	ci.mx.RUnlock()

	if !ready {
		// Because we might be sending stored packets, lock here to stop new things going to
		// the packet queue.
		hostinfo.cachePacket(message, 0, packet, f.sendMessageNow)
		return
	}

	dropReason := f.firewall.Drop(packet, *fwPacket, false, hostinfo, trustedCAs)
	if dropReason == nil {
		mc := f.sendNoMetrics(message, 0, ci, hostinfo, hostinfo.remote, packet, nb, out)
		if f.lightHouse != nil && mc%5000 == 0 {
			f.lightHouse.Query(fwPacket.RemoteIP, f)
		}

	} else {
		hostinfo.logger().Debug(
			"dropping outbound packet",
			zap.Any("fwPacket", fwPacket),
			zap.String("reason", dropReason.Error()),
		)
	}

}

// getOrHandshake returns nil if the vpnIp is not routable
func (f *Interface) getOrHandshake(vpnIp uint32) *HostInfo {
	if !f.hostMap.vpnCIDR.Contains(int2ip(vpnIp)) {
		vpnIp = f.hostMap.queryUnsafeRoute(vpnIp)
		if vpnIp == 0 {
			return nil
		}
	}
	hostinfo, err := f.hostMap.PromoteBestQueryVpnIP(vpnIp, f)

	//if err != nil || hostinfo.ConnectionState == nil {
	if err != nil {
		hostinfo, err = f.handshakeManager.pendingHostMap.QueryVpnIP(vpnIp)
		if err != nil {
			hostinfo = f.handshakeManager.AddVpnIP(vpnIp)
		}
	}

	hostinfo.RLock()
	ci := hostinfo.ConnectionState
	ready := ci.IsReady()
	hostinfo.RUnlock()

	if ready {
		return hostinfo
	}
	if ci == nil {
		// if we don't have a connection state, then send a handshake initiation
		ci = f.newConnectionState(true, noise.HandshakeIX, []byte{}, 0)
		// FIXME: Maybe make XX selectable, but probably not since psk makes it nearly pointless for us.
		//ci = f.newConnectionState(true, noise.HandshakeXX, []byte{}, 0)
		hostinfo.ConnectionState = ci
	}
	hostinfo.RLock()
	ready = hostinfo.HandshakeReady
	hostinfo.RUnlock()
	// If we have already created the handshake packet, we don't want to call the function at all.
	if !ready {
		ixHandshakeStage0(f, vpnIp, hostinfo)
		// FIXME: Maybe make XX selectable, but probably not since psk makes it nearly pointless for us.
		//xx_handshakeStage0(f, ip, hostinfo)

		// If this is a static host, we don't need to wait for the HostQueryReply
		// We can trigger the handshake right now
		if _, ok := f.lightHouse.staticList[vpnIp]; ok {
			select {
			case f.handshakeManager.trigger <- vpnIp:
			default:
			}
		}
	}

	return hostinfo
}

func (f *Interface) sendMessageNow(t NebulaMessageType, st NebulaMessageSubType, hostInfo *HostInfo, p, nb, out []byte) {
	fp := &FirewallPacket{}
	err := newPacket(p, false, fp)
	if err != nil {
		l.Sugar().Warnf("error while parsing outgoing packet for firewall check; %v", err)
		return
	}

	// check if packet is in outbound fw rules
	dropReason := f.firewall.Drop(p, *fp, false, hostInfo, trustedCAs)
	if dropReason != nil {
		l.Debug(
			"dropping cached packet",
			zap.Any("fwPacket", fp),
			zap.String("reason", dropReason.Error()),
		)
		return
	}

	f.sendNoMetrics(message, st, hostInfo.ConnectionState, hostInfo, hostInfo.remote, p, nb, out)
	if f.lightHouse != nil && *hostInfo.ConnectionState.messageCounter%5000 == 0 {
		f.lightHouse.Query(fp.RemoteIP, f)
	}
}

// SendMessageToVpnIp handles real ip:port lookup and sends to the current best known address for vpnIp
func (f *Interface) SendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte) {
	hostInfo := f.getOrHandshake(vpnIp)
	if hostInfo == nil {
		l.Debug(
			"dropping SendMessageToVpnIp, vpnIp not in our CIDR or in unsafe routes",
			zap.Uint32("vpnIp", uint32(IntIp(vpnIp))),
		)
		return
	}

	if !hostInfo.ConnectionState.ready {
		// Because we might be sending stored packets, lock here to stop new things going to
		// the packet queue.
		hostInfo.ConnectionState.queueLock.Lock()
		if !hostInfo.ConnectionState.ready {
			hostInfo.cachePacket(t, st, p, f.sendMessageToVpnIp)
			hostInfo.ConnectionState.queueLock.Unlock()
			return
		}
		hostInfo.ConnectionState.queueLock.Unlock()
	}

	f.sendMessageToVpnIp(t, st, hostInfo, p, nb, out)
}

func (f *Interface) sendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, hostInfo *HostInfo, p, nb, out []byte) {
	f.send(t, st, hostInfo.ConnectionState, hostInfo, hostInfo.remote, p, nb, out)
}

// SendMessageToAll handles real ip:port lookup and sends to all known addresses for vpnIp
func (f *Interface) SendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte) {
	hostInfo := f.getOrHandshake(vpnIp)
	if hostInfo == nil {
		l.Debug(
			"dropping SendMessageToAll, vpnIp not in our CIDR or in unsafe routes",
			zap.Uint32("vpnIp", uint32(IntIp(vpnIp))),
		)
		return
	}

	if !hostInfo.ConnectionState.ready {
		// Because we might be sending stored packets, lock here to stop new things going to
		// the packet queue.
		hostInfo.ConnectionState.queueLock.Lock()
		if !hostInfo.ConnectionState.ready {
			hostInfo.cachePacket(t, st, p, f.sendMessageToAll)
			hostInfo.ConnectionState.queueLock.Unlock()
			return
		}
		hostInfo.ConnectionState.queueLock.Unlock()
	}

	f.sendMessageToAll(t, st, hostInfo, p, nb, out)
}

func (f *Interface) sendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, hostInfo *HostInfo, p, nb, b []byte) {
	for _, r := range hostInfo.RemoteUDPAddrs() {
		f.send(t, st, hostInfo.ConnectionState, hostInfo, r, p, nb, b)
	}
}

func (f *Interface) send(t NebulaMessageType, st NebulaMessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote *udpAddr, p, nb, out []byte) {
	f.messageMetrics.Tx(t, st, 1)
	f.sendNoMetrics(t, st, ci, hostinfo, remote, p, nb, out)
}

func (f *Interface) sendNoMetrics(t NebulaMessageType, st NebulaMessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote *udpAddr, p, nb, out []byte) uint64 {
	if ci.eKey == nil {
		//TODO: log warning
		return 0
	}

	var err error
	//TODO: enable if we do more than 1 tun queue
	//ci.writeLock.Lock()
	c := atomic.AddUint64(ci.messageCounter, 1)

	//l.WithField("trace", string(debug.Stack())).Error("out Header ", &Header{Version, t, st, 0, hostinfo.remoteIndexId, c}, p)
	out = HeaderEncode(out, Version, uint8(t), uint8(st), hostinfo.remoteIndexId, c)
	f.connectionManager.Out(hostinfo.hostId)

	out, err = ci.eKey.EncryptDanger(out, out, p, c, nb)
	//TODO: see above note on lock
	//ci.writeLock.Unlock()
	if err != nil {
		hostinfo.logger().Error(
			"failed to encrypt outgoing packet",
			zap.Uint32("udpIp", remote.IP),
			zap.Uint16("udpPort", remote.Port),
			zap.Uint64("counter", c),
			zap.Uint64("attemptedCounter", *ci.messageCounter),
			zap.Error(err),
		)
		return c
	}

	err = f.outside.WriteTo(out, remote)
	if err != nil {
		hostinfo.logger().Error(
			"failed to write outgoing packet",
			zap.Uint32("udpIp", remote.IP),
			zap.Uint16("udpPort", remote.Port),
			zap.Error(err),
		)
	}
	return c
}

func isMulticast(ip uint32) bool {
	// Class D multicast
	return (((ip >> 24) & 0xff) & 0xf0) == 0xe0
}
