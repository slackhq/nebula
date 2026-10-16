package nebula

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
)

func (f *Interface) consumeInsidePacket(pkt tio.Packet, fwPacket *firewall.ParsedPacket, nb []byte, sendBatch *batch.SendBatch, rejectBuf []byte, q int, localCache firewall.ConntrackCache) {
	if hostinfo := f.filterInsidePacket(pkt, fwPacket, rejectBuf, q, localCache); hostinfo != nil {
		f.sendInsideMessage(hostinfo, pkt, nb, sendBatch)
	}
}

// filterInsidePacket parses and filters pkt, handling local traffic, destination lookup, pending handshakes and
// the outbound firewall. It returns the hostinfo to send pkt to, or nil when pkt was dropped, rejected, forwarded
// to self or cached for a pending handshake.
func (f *Interface) filterInsidePacket(pkt tio.Packet, fwPacket *firewall.ParsedPacket, rejectBuf []byte, q int, localCache firewall.ConntrackCache) *HostInfo {
	// borrowed: pkt.Bytes is owned by the originating tio.Queue and is
	// only valid until the next Read on that queue. Filtering and sending
	// must finish before then. Self-forwarding writes synchronously and the
	// handshake cache copies each segment. To retain the packet beyond the
	// next Read, use pkt.Clone() to detach it from the borrow.
	//
	// pkt.Bytes is either one IP datagram (GSO zero) or a TSO/USO
	// superpacket. In both cases the L3+L4 headers at the start describe
	// the same 5-tuple every segment will share, so a single newPacket /
	// firewall check covers the whole superpacket.
	packet := pkt.Bytes
	err := newPacket(packet, false, fwPacket)
	if err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("Error while validating outbound packet",
				"packet", packet,
				"error", err,
			)
		}
		return nil
	}

	// Ignore local broadcast packets
	if f.dropLocalBroadcast {
		if f.myBroadcastAddrsTable.Contains(fwPacket.RemoteAddr) {
			return nil
		}
	}

	if f.myVpnAddrsTable.Contains(fwPacket.RemoteAddr) {
		// Immediately forward packets from self to self.
		// This should only happen on Darwin-based and FreeBSD hosts, which
		// routes packets from the Nebula addr to the Nebula addr through the Nebula
		// TUN device.
		if immediatelyForwardToSelf {
			// Write copies into the kernel queue synchronously, so seg's lifetime ends at return.
			// A self-forwarded superpacket would be re-handed to the
			// kernel as one giant blob; segment first so the loopback
			// path sees one IP datagram per Write.
			err := tio.SegmentSuperpacket(pkt, func(seg []byte) error {
				// The kernel may have left the transport checksum for hardware
				// offload to finish; nothing between here and the tun will.
				iputil.SetTransportChecksum(seg)
				_, werr := f.queues[q].Write(seg)
				return werr
			})
			if err != nil {
				f.l.Error("Failed to forward to tun", "error", err)
			}
		}
		// Otherwise, drop. On linux, we should never see these packets - Linux
		// routes packets from the nebula addr to the nebula addr through the loopback device.
		return nil
	}

	// Ignore multicast packets
	if f.dropMulticast && fwPacket.RemoteAddr.IsMulticast() {
		return nil
	}

	hostinfo, ready := f.getOrHandshakeConsiderRouting(&fwPacket.Packet, func(hh *HandshakeHostInfo) {
		// borrowed: SegmentSuperpacket builds each segment in the kernel-supplied pkt
		// bytes underneath. cachePacket explicitly copies its argument (handshake_manager.go cachePacket),
		// so retaining segments past the loop is safe.
		err := tio.SegmentSuperpacket(pkt, func(seg []byte) error {
			hh.cachePacket(f.l, header.Message, 0, seg, f.sendMessageNow, f.cachedPacketMetrics)
			return nil
		})
		if err != nil && f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("Failed to segment superpacket for handshake cache",
				"error", err,
				"vpnAddr", fwPacket.RemoteAddr,
			)
		}
	})

	if hostinfo == nil {
		f.rejectInside(packet, rejectBuf, q)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("dropping outbound packet, vpnAddr not in our vpn networks or in unsafe networks",
				"vpnAddr", fwPacket.RemoteAddr,
				"fwPacket", fwPacket,
			)
		}
		return nil
	}

	if !ready {
		return nil
	}

	dropReason := f.firewall.Drop(fwPacket.Packet, false, hostinfo, f.pki.GetCAPool(), localCache)
	if dropReason == nil {
		return hostinfo
	}

	f.rejectInside(packet, rejectBuf, q)
	if f.l.Enabled(context.Background(), slog.LevelDebug) {
		hostinfo.logger(f.l).Debug("dropping outbound packet",
			"fwPacket", fwPacket,
			"reason", dropReason,
		)
	}
	return nil
}

// sendInsideMessage encrypts a firewall-approved inside packet (or every
// segment of a TSO/USO superpacket) into the caller's batch slot for
// later sendmmsg flush. Segmentation is fused with encryption here so the
// kernel-supplied superpacket bytes never get written into a separate
// scratch arena: SegmentSuperpacket builds each segment's plaintext in
// segScratch[:segLen] in turn, and we encrypt directly into a fresh SendBatch slot.
func (f *Interface) sendInsideMessage(hostinfo *HostInfo, pkt tio.Packet, nb []byte, sendBatch *batch.SendBatch) {
	var it txItem
	if f.prepareTxItem(&it, hostinfo, pkt) {
		f.encryptTxItem(&it, nb, sendBatch)
	}
}

// recordOutbound marks traffic out on hostinfo, once per packet or superpacket, and when we rebound since this tunnel
// last sent, asks the lighthouse to get the far side punching at us again.
func (f *Interface) recordOutbound(hostinfo *HostInfo) {
	if f.connectionManager.Out(hostinfo) {
		f.lightHouse.QueryServer(hostinfo.vpnAddrs[0])
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Lighthouse update triggered for punch due to rebind epoch", "vpnAddrs", hostinfo.vpnAddrs)
		}
	}
}

// findRelay returns the first relay that can reach hostinfo, forgetting the ones that no longer resolve.
func (f *Interface) findRelay(hostinfo *HostInfo) (*HostInfo, *Relay) {
	for _, relayIP := range hostinfo.relayState.CopyRelayIps() {
		via, relay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relayIP)
		if err == nil {
			return via, relay
		}
		hostinfo.relayState.DeleteRelay(relayIP)
		hostinfo.logger(f.l).Info("sendNoMetrics failed to find HostInfo", "relay", relayIP, "error", err)
	}
	return nil, nil
}

// encryptMessage encodes the header for counter c and encrypts p behind it into out. The caller allocates c and
// holds writeLock when the cipher requires encryption in nonce order.
func (f *Interface) encryptMessage(t header.MessageType, st header.MessageSubType, hostinfo *HostInfo, ci *ConnectionState, c uint64, p, nb, out []byte, remote netip.AddrPort) []byte {
	out = header.Encode(out, header.Version, t, st, hostinfo.remoteIndexId, c)
	out, err := ci.eKey.EncryptDanger(out, out, p, c, nb)
	if err != nil {
		hostinfo.logger(f.l).Error("Failed to encrypt outgoing packet", "error", err, "udpAddr", remote, "counter", c)
		return nil
	}
	return out
}

func (f *Interface) rejectInside(packet []byte, out []byte, q int) {
	if !f.firewall.OutboundSendReject {
		return
	}

	out = iputil.CreateRejectPacket(packet, out)
	if len(out) == 0 {
		return
	}

	_, err := f.queues[q].Write(out)
	if err != nil {
		f.l.Error("Failed to write to tun", "error", err)
	}
}

func (f *Interface) rejectOutside(packet []byte, ci *ConnectionState, hostinfo *HostInfo, nb, rejectBuf []byte, q int) {
	if !f.firewall.InboundSendReject {
		return
	}

	// split rejectBuf to make sure we have room to write the plaintext rejection, then encrypt it, without trampling anything
	// we can't re-use packet, if we need to send an icmp reject, it won't be long enough.
	half := len(rejectBuf) / 2
	encryptBuf := rejectBuf[0:0:half] //the first half of rejectBuf's capacity, len set to 0
	buildBuf := rejectBuf[half:]

	out := iputil.CreateRejectPacket(packet, buildBuf)
	if len(out) == 0 {
		return
	}

	if len(out) > iputil.MaxRejectPacketSize {
		if f.l.Enabled(context.Background(), slog.LevelInfo) {
			f.l.Info("rejectOutside: packet too big, not sending", "packet", packet, "outPacket", out)
		}
		return
	}

	f.sendNoMetrics(header.Message, 0, ci, hostinfo, netip.AddrPort{}, out, nb, encryptBuf, q)
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

func (f *Interface) sendMessageNow(t header.MessageType, st header.MessageSubType, hostinfo *HostInfo, p, nb, out []byte) {
	fp := &firewall.ParsedPacket{}
	err := newPacket(p, false, fp)
	if err != nil {
		f.l.Warn("error while parsing outgoing packet for firewall check", "error", err)
		return
	}

	// check if packet is in outbound fw rules
	dropReason := f.firewall.Drop(fp.Packet, false, hostinfo, f.pki.GetCAPool(), nil)
	if dropReason != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("dropping cached packet",
				"fwPacket", fp,
				"reason", dropReason,
			)
		}
		return
	}

	f.sendNoMetrics(header.Message, st, hostinfo.ConnectionState, hostinfo, netip.AddrPort{}, p, nb, out, 0)
}

// SendMessageToVpnAddr handles real addr:port lookup and sends to the current best known address for vpnAddr.
// This function ignores myVpnNetworksTable, and will always attempt to treat the address as a vpnAddr
func (f *Interface) SendMessageToVpnAddr(t header.MessageType, st header.MessageSubType, vpnAddr netip.Addr, p, nb, out []byte) {
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

// dropExhausted records an exhaustion drop and logs once, on the crossing send, for a spent tunnel.
func (f *Interface) dropExhausted(hostinfo *HostInfo, c uint64, msg string) {
	f.messageMetrics.TxExhausted(1)
	if c == RejectAfterMessages {
		hostinfo.logger(f.l).Error(msg)
	}
}

func (f *Interface) prepareSendVia(via *HostInfo,
	relay *Relay,
	ad,
	nb,
	out []byte,
	nocopy bool,
	c uint64,
) ([]byte, error) {
	// A nonzero c was reserved by the caller, who also did the connection manager bookkeeping
	reserved := c != 0
	locked := !reserved && noiseutil.EncryptLockNeeded
	if locked {
		// NOTE: for goboring AESGCMTLS we need to lock because of the nonce check
		via.ConnectionState.writeLock.Lock()
	}
	if !reserved {
		var ok bool
		c, ok = via.ConnectionState.NextMessageCounter()
		if !ok {
			if locked {
				via.ConnectionState.writeLock.Unlock()
			}
			f.dropExhausted(via, c, "Dropping outbound relay packets, tunnel message counter is exhausted")
			return nil, fmt.Errorf("tunnel message counter is exhausted")
		}
		f.connectionManager.OutNoRebind(via)
	}
	out = header.Encode(out, header.Version, header.Message, header.MessageRelay, relay.RemoteIndex, c)

	// Authenticate the header and payload, but do not encrypt for this message type.
	// The payload consists of the inner, unencrypted Nebula header, as well as the end-to-end encrypted payload.
	if len(out)+len(ad)+via.ConnectionState.eKey.Overhead() > cap(out) {
		if locked {
			via.ConnectionState.writeLock.Unlock()
		}
		via.logger(f.l).Error("SendVia out buffer not large enough for relay",
			"outCap", cap(out),
			"payloadLen", len(ad),
			"headerLen", len(out),
			"cipherOverhead", via.ConnectionState.eKey.Overhead(),
		)
		return nil, io.ErrShortBuffer
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
	if locked {
		via.ConnectionState.writeLock.Unlock()
	}
	if err != nil {
		via.logger(f.l).Info("Failed to EncryptDanger in sendVia", "error", err)
		return nil, err
	}
	if !reserved {
		f.connectionManager.RelayUsed(relay.LocalIndex)
	}
	return out, nil
}

// SendVia sends a payload through a Relay tunnel. No authentication or encryption is done
// to the payload for the ultimate target host, making this a useful method for sending
// handshake messages to peers through relay tunnels.
// via is the HostInfo through which the message is relayed.
// ad is the plaintext data to authenticate, but not encrypt
// nb is a buffer used to store the nonce value, re-used for performance reasons.
// out is a buffer used to store the result of the Encrypt operation
// q indicates which writer to use to send the packet.
func (f *Interface) SendVia(via *HostInfo, relay *Relay, ad, nb, out []byte, nocopy bool, q int) {
	toSend, err := f.prepareSendVia(via, relay, ad, nb, out, nocopy, 0)
	if err != nil {
		// already logged by prepareSendVia
		return
	}

	err = f.writers[q].WriteTo(toSend, via.GetRemote())
	if err != nil {
		if l, ok := logging.RateLimited(f.l, f.udpRelayTxErrLimiter); ok {
			via.logger(l).Info("Failed to WriteTo in sendVia", "error", err)
		}
	}
}

func (f *Interface) sendNoMetrics(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote netip.AddrPort, p, nb, out []byte, q int) {
	if ci.eKey == nil {
		return
	}
	useRelay := !remote.IsValid() && !hostinfo.GetRemote().IsValid()

	// The encrypt appends to out in place and a relayed packet is then wrapped in place,
	// so out has to fit the whole packet up front or the encrypt reallocates out from under SendVia.
	// We cap the MTU of tun devices and routes we create ourselves, so only a host that set a bigger MTU than we allow gets here.
	need := header.Len + len(p) + ci.eKey.Overhead()
	if useRelay {
		// The relay tunnel runs the same cipher, and adds its own header and tag
		need += header.Len + ci.eKey.Overhead()
	}
	if cap(out) < need {
		if l, ok := logging.RateLimited(f.l, f.txOversizeLimiter); ok {
			hostinfo.logger(l).Error("Dropping outbound packet, out buffer not large enough", "outCap", cap(out), "payloadLen", len(p), "relayed", useRelay)
		}
		return
	}

	fullOut := out
	if useRelay {
		// Save a header's worth of data at the front of the 'out' buffer.
		out = out[header.Len:header.Len]
	}

	if noiseutil.EncryptLockNeeded {
		// NOTE: for goboring AESGCMTLS we need to lock because of the nonce check
		ci.writeLock.Lock()
	}
	c, ok := ci.NextMessageCounter()
	if !ok {
		if noiseutil.EncryptLockNeeded {
			ci.writeLock.Unlock()
		}
		f.dropExhausted(hostinfo, c, "Dropping outbound packets, tunnel message counter is exhausted")
		return
	}

	// A closing tunnel needs neither traffic tracking nor another punch.
	if t != header.CloseTunnel {
		f.recordOutbound(hostinfo)
	}
	out = f.encryptMessage(t, st, hostinfo, ci, c, p, nb, out, remote)
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Unlock()
	}
	if out == nil {
		return
	}

	var err error
	if remote.IsValid() {
		err = f.writers[q].WriteTo(out, remote)
		if err != nil {
			if l, ok := logging.RateLimited(f.l, f.udpTxErrLimiter); ok {
				hostinfo.logger(l).Error("Failed to write outgoing packet",
					"error", err,
					"udpAddr", remote,
				)
			}
		}
	} else if hr := hostinfo.GetRemote(); hr.IsValid() {
		err = f.writers[q].WriteTo(out, hr)
		if err != nil {
			if l, ok := logging.RateLimited(f.l, f.udpTxErrLimiter); ok {
				hostinfo.logger(l).Error("Failed to write outgoing packet",
					"error", err,
					"udpAddr", hr,
				)
			}
		}
	} else {
		if via, relay := f.findRelay(hostinfo); via != nil && relay != nil {
			f.SendVia(via, relay, out, nb, fullOut[:header.Len+len(out)], true, q)
		}
	}
}
