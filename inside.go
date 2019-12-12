package nebula

import (
	"sync/atomic"

	"github.com/flynn/noise"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

func (f *Interface) consumeInsidePacket(packet []byte, fwPacket *FirewallPacket, nb, out []byte) {
	err := newPacket(packet, false, fwPacket)
	if err != nil {
		l.WithField("packet", packet).Debugf("Error while validating outbound packet: %s", err)
		return
	}

	// Ignore local broadcast packets
	if f.dropLocalBroadcast && fwPacket.RemoteIP == f.localBroadcast {
		return
	}

	// Ignore broadcast packets
	if f.dropMulticast && isMulticast(fwPacket.RemoteIP) {
		return
	}

	hostinfo := f.getOrHandshake(fwPacket.RemoteIP)
	ci := hostinfo.ConnectionState

	if ci.ready == false {
		// Because we might be sending stored packets, lock here to stop new things going to
		// the packet queue.
		ci.queueLock.Lock()
		if !ci.ready {
			hostinfo.cachePacket(message, 0, packet, f.sendMessageNow)
			ci.queueLock.Unlock()
			return
		}
		ci.queueLock.Unlock()
	}

	if !f.firewall.Drop(packet, *fwPacket, false, ci.peerCert, trustedCAs) {
		remote := hostinfo.CurrentRemote()

		if f.pathMTUDiscovery {
			dontFragment := packet[6]&(byte(layers.IPv4DontFragment)<<5) != 0
			if dontFragment {
				remoteMTU := remote.GetMTU()
				if remoteMTU > 0 && len(packet) > remoteMTU {
					icmpResponse, err := createICMPFragmentationNeeded(packet, fwPacket, remoteMTU)
					if err != nil {
						l.WithField("vpnIp", IntIp(hostinfo.hostId)).
							WithError(err).
							Error("Failed to create ICMP Destination Unreachable response")
						return
					}

					err = f.inside.WriteRaw(icmpResponse)
					if err != nil {
						l.WithField("vpnIp", IntIp(hostinfo.hostId)).
							WithError(err).
							Error("Failed to send ICMP Destination Unreachable response")
					}
					return
				}
			}
		}

		f.send(message, 0, ci, hostinfo, remote, packet, nb, out)

		if f.lightHouse != nil && *ci.messageCounter%5000 == 0 {
			f.lightHouse.Query(fwPacket.RemoteIP, f)
		}

	} else if l.Level >= logrus.DebugLevel {
		l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("fwPacket", fwPacket).
			Debugln("dropping outbound packet")
	}
}

func (f *Interface) getOrHandshake(vpnIp uint32) *HostInfo {
	hostinfo, err := f.hostMap.PromoteBestQueryVpnIP(vpnIp, f)

	//if err != nil || hostinfo.ConnectionState == nil {
	if err != nil {
		hostinfo, err = f.handshakeManager.pendingHostMap.QueryVpnIP(vpnIp)
		if err != nil {
			hostinfo = f.handshakeManager.AddVpnIP(vpnIp)
		}
	}

	ci := hostinfo.ConnectionState

	if ci != nil && ci.eKey != nil && ci.ready {
		return hostinfo
	}

	if ci == nil {
		// if we don't have a connection state, then send a handshake initiation
		ci = f.newConnectionState(true, noise.HandshakeIX, []byte{}, 0)
		// FIXME: Maybe make XX selectable, but probably not since psk makes it nearly pointless for us.
		//ci = f.newConnectionState(true, noise.HandshakeXX, []byte{}, 0)
		hostinfo.ConnectionState = ci
	} else if ci.eKey == nil {
		// if we don't have any state at all, create it
	}

	// If we have already created the handshake packet, we don't want to call the function at all.
	if !hostinfo.HandshakeReady {
		ixHandshakeStage0(f, vpnIp, hostinfo)
		// FIXME: Maybe make XX selectable, but probably not since psk makes it nearly pointless for us.
		//xx_handshakeStage0(f, ip, hostinfo)
	}

	return hostinfo
}

func (f *Interface) sendMessageNow(t NebulaMessageType, st NebulaMessageSubType, hostInfo *HostInfo, p, nb, out []byte) {
	fp := &FirewallPacket{}
	err := newPacket(p, false, fp)
	if err != nil {
		l.Warnf("error while parsing outgoing packet for firewall check; %v", err)
		return
	}

	// check if packet is in outbound fw rules
	if f.firewall.Drop(p, *fp, false, hostInfo.ConnectionState.peerCert, trustedCAs) {
		l.WithField("fwPacket", fp).Debugln("dropping cached packet")
		return
	}

	f.send(message, st, hostInfo.ConnectionState, hostInfo, hostInfo.remote, p, nb, out)
	if f.lightHouse != nil && *hostInfo.ConnectionState.messageCounter%5000 == 0 {
		f.lightHouse.Query(fp.RemoteIP, f)
	}
}

// SendMessageToVpnIp handles real ip:port lookup and sends to the current best known address for vpnIp
func (f *Interface) SendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte) {
	hostInfo := f.getOrHandshake(vpnIp)

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
	return
}

func (f *Interface) sendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, hostInfo *HostInfo, p, nb, out []byte) {
	f.send(t, st, hostInfo.ConnectionState, hostInfo, hostInfo.remote, p, nb, out)
}

// SendMessageToAll handles real ip:port lookup and sends to all known addresses for vpnIp
func (f *Interface) SendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte) {
	hostInfo := f.getOrHandshake(vpnIp)

	if hostInfo.ConnectionState.ready == false {
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
	return
}

func (f *Interface) sendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, hostInfo *HostInfo, p, nb, b []byte) {
	for _, r := range hostInfo.Remotes {
		f.send(t, st, hostInfo.ConnectionState, hostInfo, r, p, nb, b)
	}
}

func (f *Interface) send(t NebulaMessageType, st NebulaMessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote *HostInfoDest, p, nb, out []byte) {
	if ci.eKey == nil {
		//TODO: log warning
		return
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
		l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).
			WithField("udpAddr", remote.addr).WithField("counter", c).
			WithField("attemptedCounter", ci.messageCounter).
			Error("Failed to encrypt outgoing packet")
		return
	}

	err = f.outside.WriteTo(out, remote.addr)
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).
			WithField("udpAddr", remote.addr).Error("Failed to write outgoing packet")
	}
}

// NOTE: This is only used when the experimental `tun.path_mtu_discovery`
// feature is enabled.
func createICMPFragmentationNeeded(packet []byte, fwPacket *FirewallPacket, mtu int) ([]byte, error) {
	// https://tools.ietf.org/html/rfc1191#section-4
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      255,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    int2ip(fwPacket.RemoteIP),
		DstIP:    int2ip(fwPacket.LocalIP),
	}
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(
			layers.ICMPv4TypeDestinationUnreachable,
			layers.ICMPv4CodeFragmentationNeeded,
		),
		// Next-Hop MTU
		Seq: uint16(mtu),
	}
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// IP header + first 8 bytes of the original datagram's data
	ihl := int(packet[0]&0x0f) << 2
	payload := gopacket.Payload(packet[:ihl+8])

	err := gopacket.SerializeLayers(buffer, opts,
		ipLayer,
		icmpLayer,
		payload,
	)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func isMulticast(ip uint32) bool {
	// Class D multicast
	if (((ip >> 24) & 0xff) & 0xf0) == 0xe0 {
		return true
	}

	return false
}
