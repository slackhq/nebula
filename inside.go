package nebula

import (
	"context"
	"io"
	"log/slog"
	"net/netip"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
)

func (f *Interface) consumeInsidePacket(pkt tio.Packet, fwPacket *firewall.Packet, nb []byte, tx *txQueue, rejectBuf []byte, q int, localCache firewall.ConntrackCache) {
	// borrowed: pkt.Bytes is owned by the originating tio.Queue and is
	// only valid until the next Read on that queue. Every consumer below
	// (parse, self-forward, handshake cache, sendInsideMessage) reads it
	// synchronously; do not retain pkt outside this call. If a future
	// caller needs to keep the packet, use pkt.Clone() to detach it from
	// the borrow.
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
			// Write copies into the kernel queue synchronously, so seg's lifetime ends at return.
			// A self-forwarded superpacket would be re-handed to the
			// kernel as one giant blob; segment first so the loopback
			// path sees one IP datagram per Write.
			err := tio.SegmentSuperpacket(pkt, func(seg []byte) error {
				_, werr := f.queues[q].Write(seg)
				return werr
			})
			if err != nil {
				f.l.Error("Failed to forward to tun", "error", err)
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
		return
	}

	if !ready {
		return
	}

	dropReason := f.firewall.Drop(*fwPacket, false, hostinfo, f.pki.GetCAPool(), localCache)
	if dropReason == nil {
		f.sendInsideMessage(hostinfo, pkt, nb, tx, q)
	} else {
		f.rejectInside(packet, rejectBuf, q)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("dropping outbound packet",
				"fwPacket", fwPacket,
				"reason", dropReason,
			)
		}
	}
}

func (f *Interface) sendInsideEncrypt(hostinfo *HostInfo, ci *ConnectionState, seg, scratch, nb []byte) []byte {
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Lock()
	}
	c := ci.messageCounter.Add(1)

	out := header.Encode(scratch, header.Version, header.Message, 0, hostinfo.remoteIndexId, c)
	f.connectionManager.Out(hostinfo)

	out, encErr := ci.eKey.EncryptDanger(out, out, seg, c, nb)
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Unlock()
	}
	if encErr != nil {
		hostinfo.logger(f.l).Error("Failed to encrypt outgoing packet",
			"error", encErr,
			"udpAddr", hostinfo.GetRemote(),
			"counter", c,
		)
		// Skip this segment; the rest of the superpacket can still
		// go out — TCP will retransmit anything we drop here.
		return nil
	}

	return out
}

// sendInsideMessage encrypts a firewall-approved inside packet (or every
// segment of a TSO/USO superpacket) into the caller's batch slot for
// later sendmmsg flush. Segmentation is fused with encryption here so the
// kernel-supplied superpacket bytes never get written into a separate
// scratch arena: SegmentSuperpacket builds each segment's plaintext in
// segScratch[:segLen] in turn, and we encrypt directly into a fresh
// SendBatch slot.
//
// hostinfo is always the base tunnel (the hostmap resolves by vpn address);
// when routine q has an established lane to this peer, the direct path swaps
// to the lane's session and socket below. Relay and base traffic stays on
// tx.base (socket 0).
func (f *Interface) sendInsideMessage(hostinfo *HostInfo, pkt tio.Packet, nb []byte, tx *txQueue, q int) {
	ci := hostinfo.ConnectionState
	if ci.eKey == nil {
		return
	}

	sendBatch := tx.base
	remote := hostinfo.GetRemote()
	ecnEnabled := f.ecnEnabled.Load()
	if hostinfo.lastRebindCount != f.rebindCount {
		//NOTE: there is an update hole if a tunnel isn't used and exactly 256 rebinds occur before the tunnel is
		// finally used again. This tunnel would eventually be torn down and recreated if this action didn't help.
		f.lightHouse.QueryServer(hostinfo.vpnAddrs[0])
		hostinfo.lastRebindCount = f.rebindCount
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Lighthouse update triggered for punch due to rebind counter",
				"vpnAddrs", hostinfo.vpnAddrs,
			)
		}
	}

	if !remote.IsValid() { //the relay path
		//first, find our relay hostinfo:
		var relayHostInfo *HostInfo
		var relay *Relay
		var err error
		for _, relayIP := range hostinfo.relayState.CopyRelayIps() {
			relayHostInfo, relay, err = f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relayIP)
			if err != nil {
				hostinfo.relayState.DeleteRelay(relayIP)
				hostinfo.logger(f.l).Info("sendNoMetrics failed to find HostInfo",
					"relay", relayIP,
					"error", err,
				)
				continue
			}
			break
		}
		if relayHostInfo == nil || relay == nil {
			//failure already logged
			return
		}

		err = tio.SegmentSuperpacket(pkt, func(seg []byte) error {
			//relay header + header + plaintext + AEAD tag (16 bytes for both AES-GCM and ChaCha20-Poly1305) + relay tag
			scratch := sendBatch.Reserve(header.Len + header.Len + len(seg) + 16 + 16)

			innerPacket := f.sendInsideEncrypt(hostinfo, ci, seg, scratch[header.Len:], nb)
			if innerPacket == nil {
				return nil
			}

			//now we need to do a relay-encrypt:
			toSend, err := f.prepareSendVia(relayHostInfo, relay, innerPacket, nb, scratch, true)
			if err != nil {
				//already logged
				return nil
			}

			var ecn byte
			if ecnEnabled {
				ecn = innerECN(seg)
			}
			sendBatch.Commit(toSend, relayHostInfo.GetRemote(), ecn)
			return nil
		})
		if err != nil {
			hostinfo.logger(f.l).Error("Failed to segment superpacket for relay send", "error", err)
		}
		return
	}

	// Direct path: prefer this routine's lane tunnel when it is established.
	// The pointer is only published once the lane's ConnectionState is fully
	// populated, so a non-nil Load is always usable. On lane death the slot
	// CAS-clears and traffic falls back to the base tunnel instantly.
	if ls := hostinfo.lanes; ls != nil && q < len(ls.txLanes) {
		if lane := ls.txLanes[q].Load(); lane != nil {
			if lci := lane.ConnectionState; lci != nil && lci.eKey != nil {
				hostinfo = lane
				ci = lci
				remote = lane.GetRemote()
				sendBatch = tx.lane
			}
		}
	}

	err := tio.SegmentSuperpacket(pkt, func(seg []byte) error {
		// header + plaintext + AEAD tag (16 bytes for both AES-GCM and ChaCha20-Poly1305)
		scratch := sendBatch.Reserve(header.Len + len(seg) + 16)

		out := f.sendInsideEncrypt(hostinfo, ci, seg, scratch, nb)
		if out == nil {
			return nil
		}

		var ecn byte
		if ecnEnabled {
			ecn = innerECN(seg)
		}
		sendBatch.Commit(out, remote, ecn)
		return nil
	})
	if err != nil {
		hostinfo.logger(f.l).Error("Failed to segment superpacket for send",
			"error", err,
		)
	}
}

// innerECN returns the 2-bit IP-level ECN codepoint of an inner IPv4 or IPv6
// packet, or 0 if pkt is too short or its IP version is unrecognized. Used at
// encap to copy the inner codepoint onto the outer carrier per RFC 6040.
func innerECN(pkt []byte) byte {
	if len(pkt) < 2 {
		return 0
	}
	switch pkt[0] >> 4 {
	case 4:
		return pkt[1] & 0x03
	case 6:
		return (pkt[1] >> 4) & 0x03
	}
	return 0
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

func (f *Interface) rejectOutside(packet []byte, ci *ConnectionState, hostinfo *HostInfo, nb, rejectBuf []byte) {
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

	f.sendNoMetrics(header.Message, 0, ci, hostinfo, netip.AddrPort{}, out, nb, encryptBuf)
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

	f.sendNoMetrics(header.Message, st, hostinfo.ConnectionState, hostinfo, netip.AddrPort{}, p, nb, out)
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
	f.sendNoMetrics(t, st, ci, hostinfo, netip.AddrPort{}, p, nb, out)
}

func (f *Interface) sendTo(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote netip.AddrPort, p, nb, out []byte) {
	f.messageMetrics.Tx(t, st, 1)
	f.sendNoMetrics(t, st, ci, hostinfo, remote, p, nb, out)
}

func (f *Interface) prepareSendVia(via *HostInfo,
	relay *Relay,
	ad,
	nb,
	out []byte,
	nocopy bool,
) ([]byte, error) {
	if noiseutil.EncryptLockNeeded {
		// NOTE: for goboring AESGCMTLS we need to lock because of the nonce check
		via.ConnectionState.writeLock.Lock()
	}
	c := via.ConnectionState.messageCounter.Add(1)

	out = header.Encode(out, header.Version, header.Message, header.MessageRelay, relay.RemoteIndex, c)
	f.connectionManager.Out(via)

	// Authenticate the header and payload, but do not encrypt for this message type.
	// The payload consists of the inner, unencrypted Nebula header, as well as the end-to-end encrypted payload.
	if len(out)+len(ad)+via.ConnectionState.eKey.Overhead() > cap(out) {
		if noiseutil.EncryptLockNeeded {
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
	if noiseutil.EncryptLockNeeded {
		via.ConnectionState.writeLock.Unlock()
	}
	if err != nil {
		via.logger(f.l).Info("Failed to EncryptDanger in sendVia", "error", err)
		return nil, err
	}
	f.connectionManager.RelayUsed(relay.LocalIndex)
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
func (f *Interface) SendVia(via *HostInfo,
	relay *Relay,
	ad,
	nb,
	out []byte,
	nocopy bool,
) {
	toSend, err := f.prepareSendVia(via, relay, ad, nb, out, nocopy)
	if err != nil {
		// already logged by prepareSendVia
		return
	}

	// Relay carriers are base tunnels (sockIdx 0); indexing through the
	// carrier keeps the invariant explicit.
	err = f.writers[via.sockIdx].WriteTo(toSend, via.GetRemote())
	if err != nil {
		via.logger(f.l).Info("Failed to WriteTo in sendVia", "error", err)
	}
}

func (f *Interface) sendNoMetrics(t header.MessageType, st header.MessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote netip.AddrPort, p, nb, out []byte) {
	if ci.eKey == nil {
		return
	}
	// Every packet on a tunnel egresses the tunnel's own socket. For base and
	// vanilla tunnels sockIdx is 0 (stock behavior); for lanes it keeps
	// keepalives, close packets and rejects on the lane's 4-tuple so the
	// peer's spoof/roam checks accept them and the NAT entry stays warm.
	q := hostinfo.sockIdx
	useRelay := !remote.IsValid() && !hostinfo.GetRemote().IsValid()
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
	f.connectionManager.Out(hostinfo)

	// Query our LH if we haven't since the last time we've been rebound, this will cause the remote to punch against
	// all our addrs and enable a faster roaming.
	// Lanes skip this: the base tunnel issues the one query for the peer.
	if t != header.CloseTunnel && !hostinfo.isLane() && hostinfo.lastRebindCount != f.rebindCount {
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

	var err error
	out, err = ci.eKey.EncryptDanger(out, out, p, c, nb)
	if noiseutil.EncryptLockNeeded {
		ci.writeLock.Unlock()
	}
	if err != nil {
		hostinfo.logger(f.l).Error("Failed to encrypt outgoing packet",
			"error", err,
			"udpAddr", remote,
			"counter", c,
		)
		return
	}

	if remote.IsValid() {
		err = f.writers[q].WriteTo(out, remote)
		if err != nil {
			hostinfo.logger(f.l).Error("Failed to write outgoing packet",
				"error", err,
				"udpAddr", remote,
			)
		}
	} else if hr := hostinfo.GetRemote(); hr.IsValid() {
		err = f.writers[q].WriteTo(out, hr)
		if err != nil {
			hostinfo.logger(f.l).Error("Failed to write outgoing packet",
				"error", err,
				"udpAddr", remote,
			)
		}
	} else {
		if hostinfo.isLane() {
			// A lane always has a valid remote (set from its own handshake);
			// reaching here means the lane is broken, and lane ciphertext must
			// never ride a relay (relays are base-tunnel-only).
			hostinfo.logger(f.l).Error("Dropping lane packet with no valid remote")
			return
		}
		// Try to send via a relay
		for _, relayIP := range hostinfo.relayState.CopyRelayIps() {
			relayHostInfo, relay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relayIP)
			if err != nil {
				hostinfo.relayState.DeleteRelay(relayIP)
				hostinfo.logger(f.l).Info("sendNoMetrics failed to find HostInfo",
					"relay", relayIP,
					"error", err,
				)
				continue
			}
			f.SendVia(relayHostInfo, relay, out, nb, fullOut[:header.Len+len(out)], true)
			break
		}
	}
}
