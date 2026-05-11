package nebula

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/routing"
)

func (f *Interface) consumeInsidePacket(buf *WireBuffer, q int, localCache firewall.ConntrackCache) {
	packet := buf.IPPacket()

	err := newPacket(packet, false, buf.FwPacket)
	if err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("Error while validating outbound packet",
				"packet", packet,
				"error", err,
			)
		}
		return
	}

	// Ignore local broadcast packets
	if f.dropLocalBroadcast {
		if f.myBroadcastAddrsTable.Contains(buf.FwPacket.RemoteAddr) {
			return
		}
	}

	if f.myVpnAddrsTable.Contains(buf.FwPacket.RemoteAddr) {
		// Immediately forward packets from self to self.
		// This should only happen on Darwin-based and FreeBSD hosts, which
		// routes packets from the Nebula addr to the Nebula addr through the Nebula
		// TUN device.
		if immediatelyForwardToSelf {
			_, err := f.readers[q].Write(packet)
			if err != nil {
				f.l.Error("Failed to forward to tun", "error", err)
			}
		}
		// Otherwise, drop. On linux, we should never see these packets - Linux
		// routes packets from the nebula addr to the nebula addr through the loopback device.
		return
	}

	// Ignore multicast packets
	if f.dropMulticast && buf.FwPacket.RemoteAddr.IsMulticast() {
		return
	}

	hostinfo, ready := f.getOrHandshakeConsiderRouting(buf.FwPacket, func(hh *HandshakeHostInfo) {
		hh.cachePacket(f.l, header.Message, 0, packet, f.sendMessageNow, f.cachedPacketMetrics)
	})

	if hostinfo == nil {
		f.rejectInside(packet, buf.Out, q)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("dropping outbound packet, vpnAddr not in our vpn networks or in unsafe networks",
				"vpnAddr", buf.FwPacket.RemoteAddr,
				"fwPacket", buf.FwPacket,
			)
		}
		return
	}

	if !ready {
		return
	}

	dropReason := f.firewall.Drop(*buf.FwPacket, false, hostinfo, f.pki.GetCAPool(), localCache)
	if dropReason == nil {
		f.sendNoMetrics(header.Message, 0, hostinfo.ConnectionState, hostinfo, netip.AddrPort{}, packet, buf, q)

	} else {
		f.rejectInside(packet, buf.Out, q)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("dropping outbound packet",
				"fwPacket", buf.FwPacket,
				"reason", dropReason,
			)
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
		f.l.Error("Failed to write to tun", "error", err)
	}
}

func (f *Interface) rejectOutside(packet []byte, ci *ConnectionState, hostinfo *HostInfo, scratch []byte, buf *WireBuffer, q int) {
	if !f.firewall.OutSendReject {
		return
	}

	rejectIP := iputil.CreateRejectPacket(packet, scratch)
	if len(rejectIP) == 0 {
		return
	}

	if len(rejectIP) > iputil.MaxRejectPacketSize {
		if f.l.Enabled(context.Background(), slog.LevelInfo) {
			f.l.Info("rejectOutside: packet too big, not sending",
				"packet", packet,
				"outPacket", rejectIP,
			)
		}
		return
	}

	f.sendNoMetrics(header.Message, 0, ci, hostinfo, netip.AddrPort{}, rejectIP, buf, q)
}

// Handshake will attempt to initiate a tunnel with the provided vpn address. This is a no-op if the tunnel is already established or being established
// it does not check if it is within our vpn networks!
func (f *Interface) Handshake(vpnAddr netip.Addr) {
	f.handshakeManager.GetOrHandshake(vpnAddr, nil)
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

		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("Calculated gateway for ECMP not available, attempting other gateways",
				"destination", destinationAddr,
				"originalGateway", gatewayAddr,
			)
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

func (f *Interface) sendMessageNow(t header.MessageType, st header.MessageSubType, hostinfo *HostInfo, p []byte, buf *WireBuffer) {
	fp := &firewall.Packet{}
	err := newPacket(p, false, fp)
	if err != nil {
		f.l.Warn("error while parsing outgoing packet for firewall check", "error", err)
		return
	}

	// check if packet is in outbound fw rules
	dropReason := f.firewall.Drop(*fp, false, hostinfo, f.pki.GetCAPool(), nil)
	if dropReason != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("dropping cached packet",
				"fwPacket", fp,
				"reason", dropReason,
			)
		}
		return
	}

	f.sendNoMetrics(header.Message, st, hostinfo.ConnectionState, hostinfo, netip.AddrPort{}, p, buf, 0)
}

// SendMessageToVpnAddr handles real addr:port lookup and sends to the current best known address for vpnAddr.
// This function ignores myVpnNetworksTable, and will always attempt to treat the address as a vpnAddr
func (f *Interface) SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnAddr netip.Addr, p []byte, buf *WireBuffer) {
	hostInfo, ready := f.handshakeManager.GetOrHandshake(vpnAddr, func(hh *HandshakeHostInfo) {
		hh.cachePacket(f.l, t, st, p, f.SendMessageToHostInfo, f.cachedPacketMetrics)
	})

	if hostInfo == nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("dropping SendMessageToVpnAddr, vpnAddr not in our vpn networks or in unsafe routes",
				"vpnAddr", vpnAddr,
			)
		}
		return
	}

	if !ready {
		return
	}

	f.SendMessageToHostInfo(t, st, hostInfo, p, buf)
}

func (f *Interface) SendMessageToHostInfo(t header.MessageType, st header.MessageSubType, hi *HostInfo, p []byte, buf *WireBuffer) {
	f.send(t, st, hi.ConnectionState, hi, p, buf)
}

func (f *Interface) send(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, p []byte, buf *WireBuffer) {
	f.messageMetrics.Tx(t, st, 1)
	f.sendNoMetrics(t, st, ci, hostinfo, netip.AddrPort{}, p, buf, 0)
}

func (f *Interface) sendTo(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote netip.AddrPort, p []byte, buf *WireBuffer) {
	f.messageMetrics.Tx(t, st, 1)
	f.sendNoMetrics(t, st, ci, hostinfo, remote, p, buf, 0)
}

// SendVia sends a payload through a Relay tunnel. No authentication or encryption is done
// to the payload for the ultimate target host, making this a useful method for sending
// handshake messages to peers through relay tunnels.
//
// via is the HostInfo through which the message is relayed. ad is staged into
// the inner-payload slot of buf and then AAD-only sealed under via's key by
// SealRelayInPlace. The sendNoMetrics relay-forward path skips this entry
// point and calls sendViaInPlace directly because its inner ciphertext is
// already in place from the encrypt step.
func (f *Interface) SendVia(via *HostInfo, relay *Relay, ad []byte, buf *WireBuffer) {
	if header.Len+len(ad)+via.ConnectionState.eKey.Overhead() > cap(buf.Out) {
		via.logger(f.l).Error("SendVia out buffer not large enough for relay",
			"outCap", cap(buf.Out),
			"payloadLen", len(ad),
			"headerLen", header.Len,
			"cipherOverhead", via.ConnectionState.eKey.Overhead(),
		)
		return
	}
	buf.StageRelayInner(ad)
	f.sendViaInPlace(via, relay, len(ad), buf)
}

// sendViaInPlace stamps the outer relay header, AAD-seals over the [outer
// header | inner-already-staged] region, and writes the result to via.remote.
// Called from SendVia (after staging ad) and from sendNoMetrics' relay-forward
// path (where the inner ciphertext is already in place from SealForRelay).
func (f *Interface) sendViaInPlace(via *HostInfo, relay *Relay, innerLen int, buf *WireBuffer) {
	f.connectionManager.Out(via)
	out, err := buf.SealRelayInPlace(via.ConnectionState, relay.RemoteIndex, innerLen)
	if err != nil {
		via.logger(f.l).Info("Failed to EncryptDanger in sendVia", "error", err)
		return
	}
	if err := f.writers[0].WriteTo(out, via.remote); err != nil {
		via.logger(f.l).Info("Failed to WriteTo in sendVia", "error", err)
	}
	f.connectionManager.RelayUsed(relay.LocalIndex)
}

// sendNoMetrics encrypts and writes one outbound nebula packet (data, control,
// lighthouse, etc) using buf as the per-call wire scratch. When the hostinfo
// has no direct remote we encrypt into the relay-reserved slot via
// SealForRelay so sendViaInPlace can wrap it without an extra copy.
func (f *Interface) sendNoMetrics(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote netip.AddrPort, p []byte, buf *WireBuffer, q int) {
	if ci.eKey == nil {
		return
	}
	useRelay := !remote.IsValid() && !hostinfo.remote.IsValid()

	f.connectionManager.Out(hostinfo)

	// Query our LH if we haven't since the last time we've been rebound, this will cause the remote to punch against
	// all our addrs and enable a faster roaming.
	if t != header.CloseTunnel && hostinfo.lastRebindCount != f.rebindCount {
		//NOTE: there is an update hole if a tunnel isn't used and exactly 256 rebinds occur before the tunnel is
		// finally used again. This tunnel would eventually be torn down and recreated if this action didn't help.
		f.lightHouse.QueryServer(hostinfo.vpnAddrs[0])
		hostinfo.lastRebindCount = f.rebindCount
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("Lighthouse update triggered for punch due to rebind counter",
				"vpnAddrs", hostinfo.vpnAddrs,
			)
		}
	}

	var out []byte
	var err error
	if useRelay {
		out, err = buf.SealForRelay(ci, t, st, hostinfo.remoteIndexId, p)
	} else {
		out, err = buf.Seal(ci, t, st, hostinfo.remoteIndexId, p)
	}
	if err != nil {
		hostinfo.logger(f.l).Error("Failed to encrypt outgoing packet",
			"error", err,
			"udpAddr", remote,
		)
		return
	}

	switch {
	case remote.IsValid():
		if err := f.writers[q].WriteTo(out, remote); err != nil {
			hostinfo.logger(f.l).Error("Failed to write outgoing packet", "error", err, "udpAddr", remote)
		}
	case hostinfo.remote.IsValid():
		if err := f.writers[q].WriteTo(out, hostinfo.remote); err != nil {
			hostinfo.logger(f.l).Error("Failed to write outgoing packet", "error", err, "udpAddr", hostinfo.remote)
		}
	default:
		// SealForRelay placed the inner ciphertext at buf.Out[header.Len:],
		// so sendViaInPlace can wrap it with the outer relay header without
		// an extra copy.
		for _, relayIP := range hostinfo.relayState.CopyRelayIps() {
			relayHostInfo, relay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relayIP)
			if err != nil {
				hostinfo.relayState.DeleteRelay(relayIP)
				hostinfo.logger(f.l).Info("sendNoMetrics failed to find HostInfo", "relay", relayIP, "error", err)
				continue
			}
			f.sendViaInPlace(relayHostInfo, relay, len(out), buf)
			break
		}
	}
}
