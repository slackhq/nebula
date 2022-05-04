package nebula

import (
	"sync/atomic"

	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/udp"
)

func (f *Interface) consumeInsidePacket(packet []byte, fwPacket *firewall.Packet, nb, out []byte, q int, localCache firewall.ConntrackCache) {
	err := newPacket(packet, false, fwPacket)
	if err != nil {
		f.l.WithField("packet", packet).Debugf("Error while validating outbound packet: %s", err)
		return
	}

	// Ignore local broadcast packets
	if f.dropLocalBroadcast && fwPacket.RemoteIP == f.localBroadcast {
		return
	}

	// Immediately forward packets from self to self
	if fwPacket.RemoteIP == f.myVpnIp {
		_, err := f.readers[q].Write(packet)
		if err != nil {
			f.l.WithError(err).Error("Failed to forward to tun")
		}
		return
	}

	// Ignore broadcast packets
	if f.dropMulticast && isMulticast(fwPacket.RemoteIP) {
		return
	}

	hostinfo := f.getOrHandshake(fwPacket.RemoteIP)
	if hostinfo == nil {
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("vpnIp", fwPacket.RemoteIP).
				WithField("fwPacket", fwPacket).
				Debugln("dropping outbound packet, vpnIp not in our CIDR or in unsafe routes")
		}
		return
	}
	ci := hostinfo.ConnectionState

	if ci.ready == false {
		// Because we might be sending stored packets, lock here to stop new things going to
		// the packet queue.
		ci.queueLock.Lock()
		if !ci.ready {
			hostinfo.cachePacket(f.l, header.Message, 0, packet, f.sendMessageNow, f.cachedPacketMetrics)
			ci.queueLock.Unlock()
			return
		}
		ci.queueLock.Unlock()
	}

	dropReason := f.firewall.Drop(packet, *fwPacket, false, hostinfo, f.caPool, localCache)
	if dropReason == nil {
		f.sendNoMetrics(header.Message, 0, ci, hostinfo, nil, packet, nb, out, q)

	} else if f.l.Level >= logrus.DebugLevel {
		hostinfo.logger(f.l).
			WithField("fwPacket", fwPacket).
			WithField("reason", dropReason).
			Debugln("dropping outbound packet")
	}
}

// getOrHandshake returns nil if the vpnIp is not routable
func (f *Interface) getOrHandshake(vpnIp iputil.VpnIp) *HostInfo {
	//TODO: we can find contains without converting back to bytes
	if f.hostMap.vpnCIDR.Contains(vpnIp.ToIP()) == false {
		vpnIp = f.inside.RouteFor(vpnIp)
		if vpnIp == 0 {
			return nil
		}
	}
	hostinfo, err := f.hostMap.PromoteBestQueryVpnIp(vpnIp, f)

	//if err != nil || hostinfo.ConnectionState == nil {
	if err != nil {
		hostinfo, err = f.handshakeManager.pendingHostMap.QueryVpnIp(vpnIp)
		if err != nil {
			hostinfo = f.handshakeManager.AddVpnIp(vpnIp, f.initHostInfo)
		}
	}
	ci := hostinfo.ConnectionState

	if ci != nil && ci.eKey != nil && ci.ready {
		return hostinfo
	}

	// Handshake is not ready, we need to grab the lock now before we start the handshake process
	hostinfo.Lock()
	defer hostinfo.Unlock()

	// Double check, now that we have the lock
	ci = hostinfo.ConnectionState
	if ci != nil && ci.eKey != nil && ci.ready {
		return hostinfo
	}

	// If we have already created the handshake packet, we don't want to call the function at all.
	if !hostinfo.HandshakeReady {
		ixHandshakeStage0(f, vpnIp, hostinfo)
		// FIXME: Maybe make XX selectable, but probably not since psk makes it nearly pointless for us.
		//xx_handshakeStage0(f, ip, hostinfo)

		// If this is a static host, we don't need to wait for the HostQueryReply
		// We can trigger the handshake right now
		if _, ok := f.lightHouse.GetStaticHostList()[vpnIp]; ok {
			select {
			case f.handshakeManager.trigger <- vpnIp:
			default:
			}
		}
	}

	return hostinfo
}

// initHostInfo is the init function to pass to (*HandshakeManager).AddVpnIP that
// will create the initial Noise ConnectionState
func (f *Interface) initHostInfo(hostinfo *HostInfo) {
	hostinfo.ConnectionState = f.newConnectionState(f.l, true, noise.HandshakeIX, []byte{}, 0)
}

func (f *Interface) sendMessageNow(t header.MessageType, st header.MessageSubType, hostInfo *HostInfo, p, nb, out []byte) {
	fp := &firewall.Packet{}
	err := newPacket(p, false, fp)
	if err != nil {
		f.l.Warnf("error while parsing outgoing packet for firewall check; %v", err)
		return
	}

	// check if packet is in outbound fw rules
	dropReason := f.firewall.Drop(p, *fp, false, hostInfo, f.caPool, nil)
	if dropReason != nil {
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("fwPacket", fp).
				WithField("reason", dropReason).
				Debugln("dropping cached packet")
		}
		return
	}

	f.sendNoMetrics(header.Message, st, hostInfo.ConnectionState, hostInfo, nil, p, nb, out, 0)
}

// SendMessageToVpnIp handles real ip:port lookup and sends to the current best known address for vpnIp
func (f *Interface) SendMessageToVpnIp(t header.MessageType, st header.MessageSubType, vpnIp iputil.VpnIp, p, nb, out []byte) {
	hostInfo := f.getOrHandshake(vpnIp)
	if hostInfo == nil {
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("vpnIp", vpnIp).
				Debugln("dropping SendMessageToVpnIp, vpnIp not in our CIDR or in unsafe routes")
		}
		return
	}

	if !hostInfo.ConnectionState.ready {
		// Because we might be sending stored packets, lock here to stop new things going to
		// the packet queue.
		hostInfo.ConnectionState.queueLock.Lock()
		if !hostInfo.ConnectionState.ready {
			hostInfo.cachePacket(f.l, t, st, p, f.sendMessageToVpnIp, f.cachedPacketMetrics)
			hostInfo.ConnectionState.queueLock.Unlock()
			return
		}
		hostInfo.ConnectionState.queueLock.Unlock()
	}

	f.sendMessageToVpnIp(t, st, hostInfo, p, nb, out)
	return
}

func (f *Interface) sendMessageToVpnIp(t header.MessageType, st header.MessageSubType, hostInfo *HostInfo, p, nb, out []byte) {
	f.send(t, st, hostInfo.ConnectionState, hostInfo, p, nb, out)
}

func (f *Interface) send(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, p, nb, out []byte) {
	f.messageMetrics.Tx(t, st, 1)
	f.sendNoMetrics(t, st, ci, hostinfo, nil, p, nb, out, 0)
}

func (f *Interface) sendTo(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote *udp.Addr, p, nb, out []byte) {
	f.messageMetrics.Tx(t, st, 1)
	f.sendNoMetrics(t, st, ci, hostinfo, remote, p, nb, out, 0)
}

// sendVia sends a payload through a Relay tunnel. No authentication or encryption is done
// to the payload for the ultimate target host, making this a useful method for sending
// handshake messages to peers through relay tunnels.
// via is the HostInfo through which the message is relayed.
// remoteIdx is the remote index to use in the Nebula Header, indicating which Relay tunnel
// this message is using, and ultimately which destination host the Relay should forward
// the message to.
// ad is the plaintext data to authenticate, but not encrypt
// nb is a buffer used to store the nonce value, re-used for performance reasons.
// out is a buffer used to store the result of the Encrypt operation
// q indicates which writer to use to send the packet.
func (f *Interface) SendVia(viaIfc interface{},
	remoteIdx uint32,
	ad,
	nb,
	out []byte,
	nocopy bool,
) {
	via := viaIfc.(*HostInfo)
	c := atomic.AddUint64(&via.ConnectionState.atomicMessageCounter, 1)

	out = header.Encode(out, header.Version, header.Message, header.MessageRelay, remoteIdx, c)
	f.connectionManager.Out(via.vpnIp)

	via.logger(f.l).Infof("BRAD: SendVia Capacity of out %v to contain ad (%v) to len out (%v)", cap(out), len(ad), len(out))
	// AEAD over both the header and payload for this message type.
	if len(out)+len(ad) > cap(out) {
		via.logger(f.l).Infof("BRAD: Capacity of out %v not large enough to add ad (%v) to out (%v)", cap(out), len(ad), len(out))
		return
	}

	// The header bytes are written to the 'out' slice; Grow the slice to hold the header and associated data payload.
	offset := len(out)
	out = out[:offset+len(ad)]

	// In one call path, the associated data _is_ already stored in out. In other call paths, the associated data must
	// be copied into 'out'.
	if !nocopy {
		copy(out[offset:], ad)
	}

	var err error
	via.logger(f.l).Infof("BRAD: EncryptDanger with HostInfo %v, len(out)=%v", via.vpnIp.String(), len(out))
	out, err = via.ConnectionState.eKey.EncryptDanger(out, out, nil, c, nb)
	if err != nil {
		via.logger(f.l).WithError(err).Info("BRAD: Failed to EncryptDanger in sendVia")
		return
	}
	via.logger(f.l).WithError(err).Infof("BRAD: EncryptDanger worked, len(out)=%v", len(out))
	err = f.writers[0].WriteTo(out, via.remote)
	if err != nil {
		via.logger(f.l).WithError(err).Info("BRAD: Failed to WriteTo in sendVia")
	}
}

func (f *Interface) sendNoMetrics(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote *udp.Addr, p, nb, out []byte, q int) {
	if ci.eKey == nil {
		//TODO: log warning
		return
	}
	useRelay := remote == nil && hostinfo.remote == nil
	fullOut := out

	if useRelay {
		// Save a header's worth of data at the front of the 'out' buffer.
		out = out[header.Len:]
	}

	//TODO: enable if we do more than 1 tun queue
	//ci.writeLock.Lock()
	c := atomic.AddUint64(&ci.atomicMessageCounter, 1)

	//l.WithField("trace", string(debug.Stack())).Error("out Header ", &Header{Version, t, st, 0, hostinfo.remoteIndexId, c}, p)
	out = header.Encode(out, header.Version, t, st, hostinfo.remoteIndexId, c)
	f.connectionManager.Out(hostinfo.vpnIp)

	// Query our LH if we haven't since the last time we've been rebound, this will cause the remote to punch against
	// all our IPs and enable a faster roaming.
	if t != header.CloseTunnel && hostinfo.lastRebindCount != f.rebindCount {
		//NOTE: there is an update hole if a tunnel isn't used and exactly 256 rebinds occur before the tunnel is
		// finally used again. This tunnel would eventually be torn down and recreated if this action didn't help.
		f.lightHouse.QueryServer(hostinfo.vpnIp, f)
		hostinfo.lastRebindCount = f.rebindCount
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("vpnIp", hostinfo.vpnIp).Debug("Lighthouse update triggered for punch due to rebind counter")
		}
	}

	var err error
	out, err = ci.eKey.EncryptDanger(out, out, p, c, nb)
	//TODO: see above note on lock
	//ci.writeLock.Unlock()
	if err != nil {
		hostinfo.logger(f.l).WithError(err).
			WithField("udpAddr", remote).WithField("counter", c).
			WithField("attemptedCounter", c).
			Error("Failed to encrypt outgoing packet")
		return
	}

	if remote != nil {
		hostinfo.logger(f.l).Infof("BRAD: sendNoMetrics Write with remote %v", remote.String())
		err = f.writers[q].WriteTo(out, remote)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).
				WithField("udpAddr", remote).Error("Failed to write outgoing packet")
		}
	} else if hostinfo.remote != nil {
		hostinfo.logger(f.l).Infof("BRAD: sendNoMetrics Write with hostinfo.remote %v", hostinfo.remote.String())
		err = f.writers[q].WriteTo(out, hostinfo.remote)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).
				WithField("udpAddr", remote).Error("Failed to write outgoing packet")
		}
	} else {
		// Try to send via a relay
		hostinfo.logger(f.l).Infof("BRAD: sendNoMetrics Write search for relay for %v (len=%v)", hostinfo.vpnIp.String(), len(hostinfo.relays))
		for relayIP, _ := range hostinfo.relays {
			relayHostInfo, err := f.hostMap.QueryVpnIp(relayIP)
			if err != nil {
				hostinfo.logger(f.l).WithError(err).Infof("BRAD: sendNoMetrics failed to find HostInfo for relayIP %v", relayIP)
				continue
			}
			hostinfo.logger(f.l).WithError(err).Infof("BRAD: sendNoMetrics found relay %v for target %v", relayHostInfo.vpnIp.String(), relayIP)
			relay, ok := relayHostInfo.relayForByIp[hostinfo.vpnIp]
			if !ok {
				hostinfo.logger(f.l).Infof("BRAD: sendNoMetrics relay %v does not have a relay object for target %v", relayHostInfo.vpnIp.String(), hostinfo.vpnIp.String())
				continue
			}
			hostinfo.logger(f.l).Infof("BRAD: sendNoMetrics Write with relay %v", relayHostInfo.vpnIp.String())
			f.SendVia(relayHostInfo, relay.RemoteIndex, out, nb, fullOut[:header.Len+len(out)], true)
			break
		}
	}
	return
}

func isMulticast(ip iputil.VpnIp) bool {
	// Class D multicast
	if (((ip >> 24) & 0xff) & 0xf0) == 0xe0 {
		return true
	}

	return false
}
