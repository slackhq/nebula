package nebula

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/udp"
)

var ErrOutOfWindow = errors.New("out of window packet")

func (f *Interface) readOutsidePackets(via ViaSender, out []byte, packet []byte, h *header.H, fwPacket *firewall.Packet, parsedRx *batch.RxParsed, lhf *LightHouseHandler, nb []byte, q int, localCache firewall.ConntrackCache, meta udp.RxMeta) {
	err := h.Parse(packet)
	if err != nil {
		// Hole punch packets are 0 or 1 byte big, so lets ignore printing those errors
		// TODO: record metrics for rx holepunch/punchy packets?
		if len(packet) > 1 {
			f.messageMetrics.RxInvalid(1)
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				f.l.Debug("Error while parsing inbound packet",
					"from", via,
					"error", err,
					"packet", packet,
				)
			}
		}
		return
	}

	if h.Version != header.Version {
		f.messageMetrics.RxInvalid(1)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("Unexpected header version received", "from", via)
		}
		return
	}

	// Check before processing to see if this is a expected type/subtype
	if !h.IsValidSubType() {
		f.messageMetrics.RxInvalid(1)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("Unexpected packet received", "from", via)
		}
		return
	}

	if !via.IsRelayed {
		if f.myVpnNetworksTable.Contains(via.UdpAddr.Addr()) {
			f.messageMetrics.RxInvalid(1)
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				f.l.Debug("Refusing to process double encrypted packet", "from", via)
			}
			return
		}
	}

	// don't keep Rx metrics for message type, since you can see those in the tun metrics
	if h.Type != header.Message {
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
	}

	// Unencrypted packets
	switch h.Type {
	case header.Handshake:
		f.handshakeManager.HandleIncoming(via, packet, h)
		return

	case header.RecvError:
		f.handleRecvError(via.UdpAddr, h)
		return
	}

	// Relay packets are special
	isMessageRelay := (h.Type == header.Message && h.Subtype == header.MessageRelay)

	var hostinfo *HostInfo
	if isMessageRelay {
		hostinfo = f.hostMap.QueryRelayIndex(h.RemoteIndex)
	} else {
		hostinfo = f.hostMap.QueryIndex(h.RemoteIndex)
	}

	// At this point we should have a valid existing tunnel, verify and send
	// recvError if necessary
	if hostinfo == nil || hostinfo.ConnectionState == nil {
		if !via.IsRelayed {
			f.maybeSendRecvError(via.UdpAddr, h.RemoteIndex)
		}
		return
	}

	// All remaining packets are encrypted
	ci := hostinfo.ConnectionState
	if !ci.window.Check(f.l, h.MessageCounter) {
		return
	}

	// Relay packets are special
	if isMessageRelay {
		f.handleOutsideRelayPacket(hostinfo, via, out, packet, h, fwPacket, lhf, nb, q, localCache)

		return
	}

	out, err = f.decrypt(hostinfo, h.MessageCounter, out, packet, h, nb)
	if err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Failed to decrypt packet",
				"error", err,
				"from", via,
				"header", h,
			)
		}
		return
	}

	// Roam before we respond
	f.handleHostRoaming(hostinfo, via)
	f.connectionManager.In(hostinfo)

	switch h.Type {
	case header.Message:
		switch h.Subtype {
		case header.MessageNone:
			f.handleOutsideMessagePacket(hostinfo, out, packet, fwPacket, parsedRx, nb, q, localCache, meta)
		default:
			hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected message subtype seen", "from", via, "header", h)
			return
		}

	case header.LightHouse:
		//TODO: assert via is not relayed
		lhf.HandleRequest(via.UdpAddr, hostinfo.vpnAddrs, out, f)

	case header.Test:
		switch h.Subtype {
		case header.TestReply:
			// No-op, useful for the Roaming and connectionManager side-effects above
		case header.TestRequest:
			f.send(header.Test, header.TestReply, ci, hostinfo, out, nb, out)
		default:
			hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected test subtype seen", "from", via, "header", h)
			return
		}

	case header.CloseTunnel:
		hostinfo.logger(f.l).Info("Close tunnel received, tearing down.", "from", via)
		f.closeTunnel(hostinfo)

	case header.Control:
		f.relayManager.HandleControlMsg(hostinfo, out, f)

	default:
		hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected message type seen", "from", via, "header", h)
	}
}

func (f *Interface) handleOutsideRelayPacket(hostinfo *HostInfo, via ViaSender, out []byte, packet []byte, h *header.H, fwPacket *firewall.Packet, parsedRx *batch.RxParsed,  lhf *LightHouseHandler, nb []byte, q int, localCache firewall.ConntrackCache, meta udp.RxMeta) {
	// The entire body is sent as AD, not encrypted.
	// The packet consists of a 16-byte parsed Nebula header, Associated Data-protected payload, and a trailing 16-byte AEAD signature value.
	// The packet is guaranteed to be at least 16 bytes at this point, b/c it got past the h.Parse() call above. If it's
	// otherwise malformed (meaning, there is no trailing 16 byte AEAD value), then this will result in at worst a 0-length slice
	// which will gracefully fail in the DecryptDanger call.
	signedPayload := packet[:len(packet)-hostinfo.ConnectionState.dKey.Overhead()]
	signatureValue := packet[len(packet)-hostinfo.ConnectionState.dKey.Overhead():]
	var err error
	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, signedPayload, signatureValue, h.MessageCounter, nb)
	if err != nil {
		return
	}
	// Successfully validated the thing. Get rid of the Relay header.
	signedPayload = signedPayload[header.Len:]
	// Pull the Roaming parts up here, and return in all call paths.
	f.handleHostRoaming(hostinfo, via)
	// Track usage of both the HostInfo and the Relay for the received & authenticated packet
	f.connectionManager.In(hostinfo)
	f.connectionManager.RelayUsed(h.RemoteIndex)

	relay, ok := hostinfo.relayState.QueryRelayForByIdx(h.RemoteIndex)
	if !ok {
		// The only way this happens is if hostmap has an index to the correct HostInfo, but the HostInfo is missing
		// its internal mapping. This should never happen.
		hostinfo.logger(f.l).Error("HostInfo missing remote relay index",
			"vpnAddrs", hostinfo.vpnAddrs,
			"remoteIndex", h.RemoteIndex,
		)
		return
	}

	switch relay.Type {
	case TerminalType:
		// If I am the target of this relay, process the unwrapped packet
		// From this recursive point, all these variables are 'burned'. We shouldn't rely on them again.
		via = ViaSender{
			UdpAddr:   via.UdpAddr,
			relayHI:   hostinfo,
			remoteIdx: relay.RemoteIndex,
			relay:     relay,
			IsRelayed: true,
		}
		f.readOutsidePackets(via, out[:0], signedPayload, h, fwPacket, parsedRx, lhf, nb, q, localCache, meta)
		return
	case ForwardingType:
		// Find the target HostInfo relay object
		targetHI, targetRelay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relay.PeerAddr)
		if err != nil {
			hostinfo.logger(f.l).Info("Failed to find target host info by ip",
				"relayTo", relay.PeerAddr,
				"error", err,
				"hostinfo.vpnAddrs", hostinfo.vpnAddrs,
			)
			return
		}

		// If that relay is Established, forward the payload through it
		if targetRelay.State == Established {
			switch targetRelay.Type {
			case ForwardingType:
				// Forward this packet through the relay tunnel
				// Find the target HostInfo //todo it would potentially be nice to batch these
				f.SendVia(targetHI, targetRelay, signedPayload, nb, out, false)
			case TerminalType:
				hostinfo.logger(f.l).Error("Unexpected Relay Type of Terminal")
				return
			default:
				if f.l.Enabled(context.Background(), slog.LevelDebug) {
					hostinfo.logger(f.l).Debug("Unexpected targetRelay Type", "from", via, "relayType", targetRelay.Type)
				}
				return
			}
		} else {
			hostinfo.logger(f.l).Info("Unexpected target relay state",
				"relayTo", relay.PeerAddr,
				"relayFrom", hostinfo.vpnAddrs[0],
				"targetRelayState", targetRelay.State,
			)
			return
		}
	default:
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Unexpected relay type", "from", via, "relayType", relay.Type)
		}
	}
}

// closeTunnel closes a tunnel locally, it does not send a closeTunnel packet to the remote
func (f *Interface) closeTunnel(hostInfo *HostInfo) {
	final := f.hostMap.DeleteHostInfo(hostInfo)
	if final {
		// We no longer have any tunnels with this vpn addr, clear learned lighthouse state to lower memory usage
		f.lightHouse.DeleteVpnAddrs(hostInfo.vpnAddrs)
	}
}

// sendCloseTunnel is a helper function to send a proper close tunnel packet to a remote
func (f *Interface) sendCloseTunnel(h *HostInfo) {
	f.send(header.CloseTunnel, 0, h.ConnectionState, h, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
}

func (f *Interface) handleHostRoaming(hostinfo *HostInfo, via ViaSender) {
	if !via.IsRelayed && hostinfo.remote != via.UdpAddr {
		if !f.lightHouse.GetRemoteAllowList().AllowAll(hostinfo.vpnAddrs, via.UdpAddr.Addr()) {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(f.l).Debug("lighthouse.remote_allow_list denied roaming", "newAddr", via.UdpAddr)
			}
			return
		}

		if !hostinfo.lastRoam.IsZero() && via.UdpAddr == hostinfo.lastRoamRemote && time.Since(hostinfo.lastRoam) < RoamingSuppressSeconds*time.Second {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(f.l).Debug("Suppressing roam back to previous remote",
					"suppressSeconds", RoamingSuppressSeconds,
					"udpAddr", hostinfo.remote,
					"newAddr", via.UdpAddr,
				)
			}
			return
		}

		hostinfo.logger(f.l).Info("Host roamed to new udp ip/port.",
			"udpAddr", hostinfo.remote,
			"newAddr", via.UdpAddr,
		)
		hostinfo.lastRoam = time.Now()
		hostinfo.lastRoamRemote = hostinfo.remote
		hostinfo.SetRemote(via.UdpAddr)
	}

}

var (
	ErrPacketTooShort          = errors.New("packet is too short")
	ErrUnknownIPVersion        = errors.New("packet is an unknown ip version")
	ErrIPv4InvalidHeaderLength = errors.New("invalid ipv4 header length")
	ErrIPv4PacketTooShort      = errors.New("ipv4 packet is too short")
	ErrIPv6PacketTooShort      = errors.New("ipv6 packet is too short")
	ErrIPv6CouldNotFindPayload = errors.New("could not find payload in ipv6 packet")
)

// newPacket validates and parses the interesting bits for the firewall out of the ip and sub protocol headers
// newPacket parses data into a fully-hydrated firewall.Packet — kept as a
// thin wrapper around newPacketKey + Hydrate so there's one source of
// parse logic. Callers that don't need the netip.Addr-rich form (e.g.
// conntrack-only paths) should use newPacketKey directly.
func newPacket(data []byte, incoming bool, fp *firewall.Packet) error {
	var parsed batch.RxParsed
	if err := batch.ParsePacket(data, incoming, &parsed); err != nil {
		return err
	}
	parsed.Key.Hydrate(fp)
	return nil
}

func (f *Interface) decrypt(hostinfo *HostInfo, mc uint64, out []byte, packet []byte, h *header.H, nb []byte) ([]byte, error) {
	var err error
	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, packet[:header.Len], packet[header.Len:], mc, nb)
	if err != nil {
		return nil, err
	}

	if !hostinfo.ConnectionState.window.Update(f.l, mc) {
		return nil, ErrOutOfWindow
	}

	return out, nil
}

// 2-bit IP-level ECN codepoints (lower bits of IPv4 ToS / IPv6 TC).
const (
	ecnNotECT = 0x00
	ecnECT1   = 0x01
	ecnECT0   = 0x02
	ecnCE     = 0x03
)

// applyOuterECN folds an outer CE mark from the underlay into the inner
// IP header per RFC 6040 normal mode. It mutates pkt[1] in place. Other
// codepoints are advisory only and leave the inner unchanged.
//
// Merge cases (outer × inner → action):
//
//	outer != CE                : no-op (inner is authoritative)
//	outer == CE, inner Not-ECT : log; cannot propagate to a non-ECN host
//	outer == CE, inner ECT/CE  : rewrite inner ECN to CE
func applyOuterECN(pkt []byte, outerECN byte, hostinfo *HostInfo, l *slog.Logger) {
	if outerECN&ecnCE != ecnCE || len(pkt) < 2 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		switch pkt[1] & 0x03 {
		case ecnNotECT:
			if l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(l).Debug("RFC 6040: outer CE on inner Not-ECT, leaving inner unchanged")
			}
		case ecnCE:
			// Already CE.
		default:
			pkt[1] = (pkt[1] &^ 0x03) | ecnCE
		}
	case 6:
		switch (pkt[1] >> 4) & 0x03 {
		case ecnNotECT:
			if l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(l).Debug("RFC 6040: outer CE on inner Not-ECT, leaving inner unchanged")
			}
		case ecnCE:
			// Already CE.
		default:
			pkt[1] = (pkt[1] &^ 0x30) | (ecnCE << 4)
		}
	}
}

func (f *Interface) handleOutsideMessagePacket(hostinfo *HostInfo, out []byte, packet []byte, fwPacket *firewall.Packet, parsedRx *batch.RxParsed, nb []byte, q int, localCache firewall.ConntrackCache, meta udp.RxMeta) {
	// RFC 6040 normal-mode combine: fold any outer CE mark stamped by the
	// underlay into the inner header before firewall + TUN write. Other
	// outer codepoints are advisory only — we keep the inner unchanged.
	if f.ecnEnabled.Load() {
		applyOuterECN(out, meta.OuterECN, hostinfo, f.l)
	}

	// Single IP+L4 walk feeds the firewall conntrack key (parsedRx.Key)
	// and the batcher hint (parsedRx.tcp/udp). Replaces newPacket — and
	// pointedly does NOT fill fwPacket.LocalAddr/RemoteAddr, since
	// firewall.Drop's fast path uses Key alone and only hydrates fwPacket
	// from Key on the slow path.
	*fwPacket = firewall.Packet{}
	err := batch.ParsePacket(out, true, parsedRx)
	if err != nil {
		hostinfo.logger(f.l).Warn("Error while validating inbound packet",
			"error", err,
			"packet", out,
		)
		return
	}

	dropReason := f.firewall.Drop(parsedRx.Key, fwPacket, true, hostinfo, f.pki.GetCAPool(), localCache)
	if dropReason != nil {
		// NOTE: We give `packet` as the `out` here since we already decrypted from it and we don't need it anymore
		// This gives us a buffer to build the reject packet in
		f.rejectOutside(out, hostinfo.ConnectionState, hostinfo, nb, packet, q)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("dropping inbound packet",
				"fwPacket", fwPacket,
				"reason", dropReason,
			)
		}
		return
	}

	err = f.batchers[q].CommitInbound(out, parsedRx)
	if err != nil {
		f.l.Error("Failed to write to tun", "error", err)
	}
}

func (f *Interface) maybeSendRecvError(endpoint netip.AddrPort, index uint32) {
	if f.sendRecvErrorConfig.ShouldRecvError(endpoint) {
		f.sendRecvError(endpoint, index)
	}
}

func (f *Interface) sendRecvError(endpoint netip.AddrPort, index uint32) {
	f.messageMetrics.Tx(header.RecvError, 0, 1)

	b := header.Encode(make([]byte, header.Len), header.Version, header.RecvError, 0, index, 0)
	_ = f.outside.WriteTo(b, endpoint)
	if f.l.Enabled(context.Background(), slog.LevelDebug) {
		f.l.Debug("Recv error sent",
			"index", index,
			"udpAddr", endpoint,
		)
	}
}

func (f *Interface) handleRecvError(addr netip.AddrPort, h *header.H) {
	if !f.acceptRecvErrorConfig.ShouldRecvError(addr) {
		f.l.Debug("Recv error received, ignoring",
			"index", h.RemoteIndex,
			"udpAddr", addr,
		)
		return
	}

	if f.l.Enabled(context.Background(), slog.LevelDebug) {
		f.l.Debug("Recv error received",
			"index", h.RemoteIndex,
			"udpAddr", addr,
		)
	}

	hostinfo := f.hostMap.QueryReverseIndex(h.RemoteIndex)
	if hostinfo == nil {
		f.l.Debug("Did not find remote index in main hostmap", "remoteIndex", h.RemoteIndex)
		return
	}

	if hostinfo.remote.IsValid() && hostinfo.remote != addr {
		f.l.Info("Someone spoofing recv_errors?",
			"addr", addr,
			"hostinfoRemote", hostinfo.remote,
		)
		return
	}

	f.closeTunnel(hostinfo)
	// We also delete it from pending hostmap to allow for fast reconnect.
	f.handshakeManager.DeleteHostInfo(hostinfo)
}
