package nebula

import (
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/routing"
)

func (f *Interface) consumeInsidePacket(packet []byte, fwPacket *firewall.Packet, nb, out []byte, q int, localCache firewall.ConntrackCache) {
	err := newPacket(packet, false, fwPacket)
	if err != nil {
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("packet", packet).Debugf("Error while validating outbound packet: %s", err)
		}
		return
	}

	// Ignore local broadcast packets
	if f.dropLocalBroadcast {
		if f.myBroadcastAddrsTable.Contains(fwPacket.RemoteAddr) {
			return
		}
	}

	if f.myVpnAddrsTable.Contains(fwPacket.RemoteAddr) {
		// Immediately forward packets from self to self.
		// This should only happen on Darwin-based and FreeBSD hosts, which
		// routes packets from the Nebula addr to the Nebula addr through the Nebula
		// TUN device.
		if immediatelyForwardToSelf {
			_, err := f.readers[q].Write(packet)
			if err != nil {
				f.l.WithError(err).Error("Failed to forward to tun")
			}
		}
		// Otherwise, drop. On linux, we should never see these packets - Linux
		// routes packets from the nebula addr to the nebula addr through the loopback device.
		return
	}

	// Ignore multicast packets
	if f.dropMulticast && fwPacket.RemoteAddr.IsMulticast() {
		return
	}

	hostinfo, ready := f.getOrHandshakeConsiderRouting(fwPacket, func(hh *HandshakeHostInfo) {
		hh.cachePacket(f.l, header.Message, 0, packet, f.sendMessageNow, f.cachedPacketMetrics)
	})

	if hostinfo == nil {
		f.rejectInside(packet, out, q)
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("vpnAddr", fwPacket.RemoteAddr).
				WithField("fwPacket", fwPacket).
				Debugln("dropping outbound packet, vpnAddr not in our vpn networks or in unsafe networks")
		}
		return
	}

	if !ready {
		return
	}

	dropReason := f.firewall.Drop(*fwPacket, false, hostinfo, f.pki.GetCAPool(), localCache)
	if dropReason == nil {
		f.sendNoMetrics(header.Message, 0, hostinfo.ConnectionState, hostinfo, netip.AddrPort{}, packet, nb, out, q)

	} else {
		f.rejectInside(packet, out, q)
		if f.l.Level >= logrus.DebugLevel {
			hostinfo.logger(f.l).
				WithField("fwPacket", fwPacket).
				WithField("reason", dropReason).
				Debugln("dropping outbound packet")
		}
	}
}

func (f *Interface) rejectInside(packet []byte, out []byte, q int) {
	if !f.firewall.InSendReject {
		return
	}

	out = iputil.CreateRejectPacket(packet, out)
	if len(out) == 0 {
		return
	}

	_, err := f.readers[q].Write(out)
	if err != nil {
		f.l.WithError(err).Error("Failed to write to tun")
	}
}

func (f *Interface) rejectOutside(packet []byte, ci *ConnectionState, hostinfo *HostInfo, nb, out []byte, q int) {
	if !f.firewall.OutSendReject {
		return
	}

	out = iputil.CreateRejectPacket(packet, out)
	if len(out) == 0 {
		return
	}

	if len(out) > iputil.MaxRejectPacketSize {
		if f.l.GetLevel() >= logrus.InfoLevel {
			f.l.
				WithField("packet", packet).
				WithField("outPacket", out).
				Info("rejectOutside: packet too big, not sending")
		}
		return
	}

	f.sendNoMetrics(header.Message, 0, ci, hostinfo, netip.AddrPort{}, out, nb, packet, q)
}

// Handshake will attempt to initiate a tunnel with the provided vpn address if it is within our vpn networks. This is a no-op if the tunnel is already established or being established
func (f *Interface) Handshake(vpnAddr netip.Addr) {
	f.getOrHandshakeNoRouting(vpnAddr, nil)
}

// getOrHandshakeNoRouting returns nil if the vpnAddr is not routable.
// If the 2nd return var is false then the hostinfo is not ready to be used in a tunnel
func (f *Interface) getOrHandshakeNoRouting(vpnAddr netip.Addr, cacheCallback func(*HandshakeHostInfo)) (*HostInfo, bool) {
	if f.myVpnNetworksTable.Contains(vpnAddr) {
		return f.handshakeManager.GetOrHandshake(vpnAddr, cacheCallback)
	}

	return nil, false
}

// getOrHandshakeConsiderRouting will try to find the HostInfo to handle this packet, starting a handshake if necessary.
// If the 2nd return var is false then the hostinfo is not ready to be used in a tunnel.
func (f *Interface) getOrHandshakeConsiderRouting(fwPacket *firewall.Packet, cacheCallback func(*HandshakeHostInfo)) (*HostInfo, bool) {

	destinationAddr := fwPacket.RemoteAddr

	hostinfo, ready := f.getOrHandshakeNoRouting(destinationAddr, cacheCallback)

	// Host is inside the mesh, no routing required
	if hostinfo != nil {
		return hostinfo, ready
	}

	gateways := f.inside.RoutesFor(destinationAddr)

	switch len(gateways) {
	case 0:
		return nil, false
	case 1:
		// Single gateway route
		return f.handshakeManager.GetOrHandshake(gateways[0].Addr(), cacheCallback)
	default:
		// Multi gateway route, perform ECMP categorization
		gatewayAddr, balancingOk := routing.BalancePacket(fwPacket, gateways)

		if !balancingOk {
			// This happens if the gateway buckets were not calculated, this _should_ never happen
			f.l.Error("Gateway buckets not calculated, fallback from ECMP to random routing. Please report this bug.")
		}

		var handshakeInfoForChosenGateway *HandshakeHostInfo
		var hhReceiver = func(hh *HandshakeHostInfo) {
			handshakeInfoForChosenGateway = hh
		}

		// Store the handshakeHostInfo for later.
		// If this node is not reachable we will attempt other nodes, if none are reachable we will
		// cache the packet for this gateway.
		if hostinfo, ready = f.handshakeManager.GetOrHandshake(gatewayAddr, hhReceiver); ready {
			return hostinfo, true
		}

		// It appears the selected gateway cannot be reached, find another gateway to fallback on.
		// The current implementation breaks ECMP but that seems better than no connectivity.
		// If ECMP is also required when a gateway is down then connectivity status
		// for each gateway needs to be kept and the weights recalculated when they go up or down.
		// This would also need to interact with unsafe_route updates through reloading the config or
		// use of the use_system_route_table option

		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("destination", destinationAddr).
				WithField("originalGateway", gatewayAddr).
				Debugln("Calculated gateway for ECMP not available, attempting other gateways")
		}

		for i := range gateways {
			// Skip the gateway that failed previously
			if gateways[i].Addr() == gatewayAddr {
				continue
			}

			// We do not need the HandshakeHostInfo since we cache the packet in the originally chosen gateway
			if hostinfo, ready = f.handshakeManager.GetOrHandshake(gateways[i].Addr(), nil); ready {
				return hostinfo, true
			}
		}

		// No gateways reachable, cache the packet in the originally chosen gateway
		cacheCallback(handshakeInfoForChosenGateway)
		return hostinfo, false
	}

}

func (f *Interface) sendMessageNow(t header.MessageType, st header.MessageSubType, hostinfo *HostInfo, p, nb, out []byte) {
	fp := &firewall.Packet{}
	err := newPacket(p, false, fp)
	if err != nil {
		f.l.Warnf("error while parsing outgoing packet for firewall check; %v", err)
		return
	}

	// check if packet is in outbound fw rules
	dropReason := f.firewall.Drop(*fp, false, hostinfo, f.pki.GetCAPool(), nil)
	if dropReason != nil {
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("fwPacket", fp).
				WithField("reason", dropReason).
				Debugln("dropping cached packet")
		}
		return
	}

	f.sendNoMetrics(header.Message, st, hostinfo.ConnectionState, hostinfo, netip.AddrPort{}, p, nb, out, 0)
}

// SendMessageToVpnAddr handles real addr:port lookup and sends to the current best known address for vpnAddr
func (f *Interface) SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnAddr netip.Addr, p, nb, out []byte) {
	hostInfo, ready := f.getOrHandshakeNoRouting(vpnAddr, func(hh *HandshakeHostInfo) {
		hh.cachePacket(f.l, t, st, p, f.SendMessageToHostInfo, f.cachedPacketMetrics)
	})

	if hostInfo == nil {
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("vpnAddr", vpnAddr).
				Debugln("dropping SendMessageToVpnAddr, vpnAddr not in our vpn networks or in unsafe routes")
		}
		return
	}

	if !ready {
		return
	}

	f.SendMessageToHostInfo(t, st, hostInfo, p, nb, out)
}

func (f *Interface) SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hi *HostInfo, p, nb, out []byte) {
	f.send(t, st, hi.ConnectionState, hi, p, nb, out)
}

func (f *Interface) send(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, p, nb, out []byte) {
	f.messageMetrics.Tx(t, st, 1)
	f.sendNoMetrics(t, st, ci, hostinfo, netip.AddrPort{}, p, nb, out, 0)
}

func (f *Interface) sendTo(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote netip.AddrPort, p, nb, out []byte) {
	f.messageMetrics.Tx(t, st, 1)
	f.sendNoMetrics(t, st, ci, hostinfo, remote, p, nb, out, 0)
}

// SendVia sends a payload through a Relay tunnel. No authentication or encryption is done
// to the payload for the ultimate target host, making this a useful method for sending
// handshake messages to peers through relay tunnels.
// via is the HostInfo through which the message is relayed.
// ad is the plaintext data to authenticate, but not encrypt
// nb is a buffer used to store the nonce value, re-used for performance reasons.
// out is a buffer used to store the result of the Encrypt operation
// q indicates which writer to use to send the packet.
func (f *Interface) SendVia(via *HostInfo,
	relay *Relay,
	ad,
	nb,
	out []byte,
	nocopy bool,
) {
	if noiseutil.EncryptLockNeeded {
		// NOTE: for goboring AESGCMTLS we need to lock because of the nonce check
		via.ConnectionState.writeLock.Lock()
	}
	c := via.ConnectionState.messageCounter.Add(1)

	out = header.Encode(out, header.Version, header.Message, header.MessageRelay, relay.RemoteIndex, c)
	f.connectionManager.Out(via.localIndexId)

	// Authenticate the header and payload, but do not encrypt for this message type.
	// The payload consists of the inner, unencrypted Nebula header, as well as the end-to-end encrypted payload.
	if len(out)+len(ad)+via.ConnectionState.eKey.Overhead() > cap(out) {
		if noiseutil.EncryptLockNeeded {
			via.ConnectionState.writeLock.Unlock()
		}
		via.logger(f.l).
			WithField("outCap", cap(out)).
			WithField("payloadLen", len(ad)).
			WithField("headerLen", len(out)).
			WithField("cipherOverhead", via.ConnectionState.eKey.Overhead()).
			Error("SendVia out buffer not large enough for relay")
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
	out, err = via.ConnectionState.eKey.EncryptDanger(out, out, nil, c, nb)
	if noiseutil.EncryptLockNeeded {
		via.ConnectionState.writeLock.Unlock()
	}
	if err != nil {
		via.logger(f.l).WithError(err).Info("Failed to EncryptDanger in sendVia")
		return
	}
	err = f.writers[0].WriteTo(out, via.remote)
	if err != nil {
		via.logger(f.l).WithError(err).Info("Failed to WriteTo in sendVia")
	}
	f.connectionManager.RelayUsed(relay.LocalIndex)
}

func (f *Interface) sendNoMetrics(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote netip.AddrPort, p, nb, out []byte, q int) {
	if ci.eKey == nil {
		return
	}
	useRelay := !remote.IsValid() && !hostinfo.remote.IsValid()
	fullOut := out

	if useRelay {
		if len(out) < header.Len {
			// out always has a capacity of mtu, but not always a length greater than the header.Len.
			// Grow it to make sure the next operation works.
			out = out[:header.Len]
		}
		// Save a header's worth of data at the front of the 'out' buffer.
		out = out[header.Len:]
	}

	if noiseutil.EncryptLockNeeded {
		// NOTE: for goboring AESGCMTLS we need to lock because of the nonce check
		ci.writeLock.Lock()
	}
	c := ci.messageCounter.Add(1)

	//l.WithField("trace", string(debug.Stack())).Error("out Header ", &Header{Version, t, st, 0, hostinfo.remoteIndexId, c}, p)
	out = header.Encode(out, header.Version, t, st, hostinfo.remoteIndexId, c)
	f.connectionManager.Out(hostinfo.localIndexId)

	// Query our LH if we haven't since the last time we've been rebound, this will cause the remote to punch against
	// all our addrs and enable a faster roaming.
	if t != header.CloseTunnel && hostinfo.lastRebindCount != f.rebindCount {
		//NOTE: there is an update hole if a tunnel isn't used and exactly 256 rebinds occur before the tunnel is
		// finally used again. This tunnel would eventually be torn down and recreated if this action didn't help.
		f.lightHouse.QueryServer(hostinfo.vpnAddrs[0])
		hostinfo.lastRebindCount = f.rebindCount
		if f.l.Level >= logrus.DebugLevel {
			f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).Debug("Lighthouse update triggered for punch due to rebind counter")
		}
	}

	var err error
	out, err = ci.eKey.EncryptDanger(out, out, p, c, nb)
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Unlock()
	}
	if err != nil {
		hostinfo.logger(f.l).WithError(err).
			WithField("udpAddr", remote).WithField("counter", c).
			WithField("attemptedCounter", c).
			Error("Failed to encrypt outgoing packet")
		return
	}

	if remote.IsValid() {
		err = f.writers[q].WriteTo(out, remote)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).
				WithField("udpAddr", remote).Error("Failed to write outgoing packet")
		}
	} else if hostinfo.remote.IsValid() {
		err = f.writers[q].WriteTo(out, hostinfo.remote)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).
				WithField("udpAddr", remote).Error("Failed to write outgoing packet")
		}
	} else {
		// Try to send via a relay
		for _, relayIP := range hostinfo.relayState.CopyRelayIps() {
			relayHostInfo, relay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relayIP)
			if err != nil {
				hostinfo.relayState.DeleteRelay(relayIP)
				hostinfo.logger(f.l).WithField("relay", relayIP).WithError(err).Info("sendNoMetrics failed to find HostInfo")
				continue
			}
			f.SendVia(relayHostInfo, relay, out, nb, fullOut[:header.Len+len(out)], true)
			break
		}
	}
}
