package nebula

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"golang.org/x/net/ipv6"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/overlay/batch"
	"golang.org/x/net/ipv4"
)

const (
	minFwPacketLen = 4
)

var ErrOutOfWindow = errors.New("out of window packet")

// readOutsidePackets processes one received underlay packet.
// Message payloads are decrypted IN PLACE, so packet must stay untouched
// by the caller until the batcher for queue q has been flushed
func (f *Interface) readOutsidePackets(via ViaSender, packet []byte, rxc *rxContext) {
	h := rxc.h
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
		hostinfo = f.hostMap.QueryIndexCached(h.RemoteIndex, rxc.hostmapCache)
	}

	// At this point we should have a valid existing tunnel, verify and send
	// recvError if necessary
	if hostinfo == nil || hostinfo.ConnectionState == nil {
		if !via.IsRelayed {
			f.maybeSendRecvError(via.UdpAddr, h.RemoteIndex, via.SockIdx)
		}
		return
	}

	// Which session decrypts this packet is the lane index in the header. Lane 0
	// is the base tunnel; a higher lane is one of the sessions derived from it.
	ci := hostinfo.ConnectionState
	lane := h.Lane()
	if lane != 0 {
		ci = hostinfo.laneSession(lane)
		if ci == nil {
			// A lane we have no session for: a stale lane from a tunnel that has
			// since rolled, or a peer sending above what it advertised. Dropping
			// silently is right for both — a recv_error would tear down a
			// perfectly good base tunnel on the strength of one odd packet.
			f.messageMetrics.RxInvalid(1)
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(f.l).Debug("Unknown multiport lane", "from", via, "header", h)
			}
			return
		}
		if isMessageRelay {
			// A relay carrier is always the base tunnel, so lane ciphertext can
			// never legitimately arrive wrapped in one.
			f.messageMetrics.RxInvalid(1)
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(f.l).Debug("Refusing relayed multiport lane packet", "from", via, "header", h)
			}
			return
		}
	}

	if len(packet) < header.Len+ci.dKey.Overhead() {
		f.messageMetrics.RxInvalid(1)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			f.l.Debug("packet too small", "from", via, "length", len(packet))
		}
		return
	}

	// All remaining packets are encrypted
	if isMessageRelay {
		// Relay packets are special, this branch should always early-return
		err = ci.VerifyRelay(f.l, h.MessageCounter, packet, rxc.nb)
		if err != nil {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(f.l).Debug("Failed to verify relay packet", "error", err, "from", via, "header", h)
			}
			return
		}
		f.handleOutsideRelayPacket(hostinfo, via, packet, rxc)
		return
	}

	out, err := ci.Decrypt(f.l, h.MessageCounter, packet, rxc.nb)
	if err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Failed to decrypt packet", "error", err, "from", via, "header", h)
		}
		return
	}

	// Roam before we respond, but only on the base tunnel: a lane's source
	// address is a per-lane 4-tuple, not the tunnel's remote, and letting it
	// roam the hostinfo would point every non-lane packet at a lane port.
	if lane == 0 {
		f.handleHostRoaming(hostinfo, via)
	}
	f.connectionManager.In(hostinfo)

	switch h.Type {
	case header.Message:
		switch h.Subtype {
		case header.MessageNone:
			f.handleOutsideMessagePacket(hostinfo, ci, h.MessageCounter, out, rxc)
		default:
			hostinfo.logger(f.l).Error("IsValidSubType was true, but unexpected message subtype seen", "from", via, "header", h)
			return
		}

	case header.LightHouse:
		//TODO: assert via is not relayed
		rxc.lhh.HandleRequest(via.UdpAddr, hostinfo.vpnAddrs, out, f)

	case header.Test:
		switch h.Subtype {
		case header.TestReply:
			// No-op, useful for the Roaming and connectionManager side-effects above
		case header.TestRequest:
			const maxCipherOverhead = 16 //todo we use this too often, needs a real importable const
			const maxOverhead = header.Len + header.Len + maxCipherOverhead + maxCipherOverhead
			if maxOverhead+len(out) > len(rxc.scratch) {
				// A reply that cannot fit in scratch is dropped no matter the log level.
				if f.l.Enabled(context.Background(), slog.LevelDebug) {
					hostinfo.logger(f.l).Debug("dropping oversized test request", "payloadLen", len(out), "from", via)
				}
				return
			}
			f.send(header.Test, header.TestReply, hostinfo.ConnectionState, hostinfo, out, rxc.nb, rxc.scratch[:0])
		case header.LaneProbe:
			f.handleLaneProbe(hostinfo, lane, out, rxc)
		case header.LaneProbeAck:
			f.handleLaneProbeAck(hostinfo, out)
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

func (f *Interface) handleOutsideRelayPacket(hostinfo *HostInfo, via ViaSender, packet []byte, rxc *rxContext) {
	h := rxc.h
	// Successfully validated the thing. Get rid of the Relay header and the AEAD tag
	signedPayload := packet[header.Len : len(packet)-hostinfo.ConnectionState.dKey.Overhead()]
	// Pull the Roaming parts up here, and return in all call paths.
	f.handleHostRoaming(hostinfo, via)
	// Track usage of both the HostInfo and the Relay for the received & authenticated packet
	f.connectionManager.In(hostinfo)
	f.connectionManager.RelayUsed(h.RemoteIndex)

	relay, ok := hostinfo.relayState.QueryRelayForByIdx(h.RemoteIndex)
	if !ok {
		// The only way this happens is if hostmap has an index to the correct HostInfo, but the HostInfo is missing
		// its internal mapping. This should never happen.
		hostinfo.logger(f.l).Error("HostInfo missing remote relay index", "relayRemoteIndex", h.RemoteIndex)
		return
	}

	switch relay.Type {
	case TerminalType:
		// If I am the target of this relay, process the unwrapped packet
		// From this recursive point, all these variables are 'burned'. We shouldn't rely on them again.
		via = ViaSender{
			UdpAddr:   via.UdpAddr,
			relayHI:   hostinfo,
			relay:     relay,
			IsRelayed: true,
			SockIdx:   via.SockIdx,
		}
		f.readOutsidePackets(via, signedPayload, rxc)
	case ForwardingType:
		// Find the target HostInfo relay object
		targetHI, targetRelay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relay.PeerAddr)
		if err != nil {
			hostinfo.logger(f.l).Info("Failed to find target host info by ip",
				"relayTo", relay.PeerAddr,
				"relayFrom", hostinfo.vpnAddrs[0],
				"error", err,
			)
			return
		}

		// If that relay is Established, forward the payload through it
		if targetRelay.State == Established {
			switch targetRelay.Type {
			case ForwardingType:
				// Forward this packet through the relay tunnel, rebuilding it in place.
				// Encode overwrites the old outer header, and the new AEAD tag lands where the old one was
				fwdBuf := packet[:0]
				//todo it would potentially be nice to batch these
				f.SendVia(targetHI, targetRelay, signedPayload, rxc.nb, fwdBuf, true, rxc.q)
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
	curRemote := hostinfo.GetRemote()
	if !via.IsRelayed && curRemote != via.UdpAddr {
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
					"udpAddr", curRemote,
					"newAddr", via.UdpAddr,
				)
			}
			return
		}

		hostinfo.logger(f.l).Info("Host roamed to new udp ip/port.",
			"udpAddr", curRemote,
			"newAddr", via.UdpAddr,
		)
		hostinfo.lastRoam = time.Now()
		hostinfo.lastRoamRemote = curRemote
		hostinfo.SetRemote(via.UdpAddr)
	}

}

var (
	ErrPacketTooShort          = errors.New("packet is too short")
	ErrUnknownIPVersion        = errors.New("packet is an unknown ip version")
	ErrIPv4InvalidHeaderLength = errors.New("invalid ipv4 header length")
	ErrIPv4PacketTooShort      = errors.New("ipv4 packet is too short")
	ErrIPv6PacketTooShort      = errors.New("ipv6 packet is too short")
)

// newPacket validates and parses the interesting bits for the firewall out of the ip and sub protocol headers
func newPacket(data []byte, incoming bool, fp *firewall.ParsedPacket) error {
	// fp is reused across packets; reset the parse byproducts so an early-error return cannot
	// leak the previous packet's offsets.
	fp.IPHdrLen = 0
	fp.FragAny = false
	if len(data) < 1 {
		return ErrPacketTooShort
	}

	version := int((data[0] >> 4) & 0x0f)
	switch version {
	case ipv4.Version:
		return parseV4(data, incoming, fp)
	case ipv6.Version:
		return parseV6(data, incoming, fp)
	}
	return ErrUnknownIPVersion
}

func parseV6(data []byte, incoming bool, fp *firewall.ParsedPacket) error {
	dataLen := len(data)
	if dataLen < ipv6.HeaderLen {
		return ErrIPv6PacketTooShort
	}

	if incoming {
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[8:24])
		fp.LocalAddr, _ = netip.AddrFromSlice(data[24:40])
	} else {
		fp.LocalAddr, _ = netip.AddrFromSlice(data[8:24])
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[24:40])
	}

	// Walk the extension header chain to the upper layer protocol. iputil.IPv6FindUpperProtocol is the single
	// source of truth for which headers are extension headers, so this stays in lockstep with the reject path
	// and cannot drift into misreading an unknown protocol (SCTP, GRE, etc.) as a forged transport.
	proto, offset, isFragment, anyFragment, err := iputil.IPv6FindUpperProtocol(data)
	if err != nil {
		return ErrIPv6PacketTooShort
	}

	fp.Protocol = proto
	fp.Fragment = isFragment
	fp.FragAny = anyFragment
	fp.IPHdrLen = offset
	if isFragment {
		// Non-first fragments carry no transport header, so we have no ports to read
		fp.RemotePort = 0
		fp.LocalPort = 0
		return nil
	}

	switch proto {
	case iputil.IPProtocolICMPv6:
		// An ICMPv6 message is at least type, code and checksum, 4 bytes. Only echo carries more than we read.
		if dataLen < offset+4 {
			return ErrIPv6PacketTooShort
		}
		fp.LocalPort = 0      //incoming vs outgoing doesn't matter for icmpv6
		switch data[offset] { //icmp type
		case iputil.ICMPv6TypeEchoRequest, iputil.ICMPv6TypeEchoReply:
			if dataLen < offset+6 {
				return ErrIPv6PacketTooShort
			}
			fp.RemotePort = binary.BigEndian.Uint16(data[offset+4 : offset+6]) //identifier
		default:
			fp.RemotePort = 0
		}

	case iputil.IPProtocolTCP, iputil.IPProtocolUDP:
		if dataLen < offset+4 {
			return ErrIPv6PacketTooShort
		}
		if incoming {
			fp.RemotePort = binary.BigEndian.Uint16(data[offset : offset+2])
			fp.LocalPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		} else {
			fp.LocalPort = binary.BigEndian.Uint16(data[offset : offset+2])
			fp.RemotePort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		}

	default:
		// don't set ports for protocols Nebula doesn't inspect
		fp.RemotePort = 0
		fp.LocalPort = 0
	}

	return nil
}

func parseV4(data []byte, incoming bool, fp *firewall.ParsedPacket) error {
	// Do we at least have an ipv4 header worth of data?
	if len(data) < ipv4.HeaderLen {
		return ErrIPv4PacketTooShort
	}

	// Adjust our start position based on the advertised ip header length
	ihl := int(data[0]&0x0f) << 2

	// Well-formed ip header length?
	if ihl < ipv4.HeaderLen {
		return ErrIPv4InvalidHeaderLength
	}

	// Check if this is the second or further fragment of a fragmented packet.
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	fp.Fragment = (flagsfrags & 0x1FFF) != 0
	// Any fragmentation at all (MF or offset): first fragments have readable ports for the
	// firewall but must never be coalesced.
	fp.FragAny = (flagsfrags & 0x3fff) != 0
	fp.IPHdrLen = ihl

	// Firewall handles protocol checks
	fp.Protocol = data[9]

	// Accounting for a variable header length, do we have enough data for our src/dst tuples?
	minLen := ihl
	if !fp.Fragment {
		if fp.Protocol == iputil.IPProtocolICMP {
			minLen += minFwPacketLen + 2
		} else {
			minLen += minFwPacketLen
		}
	}

	if len(data) < minLen {
		return ErrIPv4InvalidHeaderLength
	}

	if incoming { // Firewall packets are locally oriented
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[12:16])
		fp.LocalAddr, _ = netip.AddrFromSlice(data[16:20])
	} else {
		fp.LocalAddr, _ = netip.AddrFromSlice(data[12:16])
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[16:20])
	}

	if fp.Fragment {
		fp.RemotePort = 0
		fp.LocalPort = 0
	} else if fp.Protocol == iputil.IPProtocolICMP { //note that orientation doesn't matter on ICMP
		fp.RemotePort = binary.BigEndian.Uint16(data[ihl+4 : ihl+6]) //identifier
		fp.LocalPort = 0                                             //code would be uint16(data[ihl+1])
	} else if incoming {
		fp.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])  //src port
		fp.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4]) //dst port
	} else {
		fp.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])    //src port
		fp.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4]) //dst port
	}

	return nil
}

func (f *Interface) handleOutsideMessagePacket(hostinfo *HostInfo, ci *ConnectionState, messageCounter uint64, out []byte, rxc *rxContext) {
	err := newPacket(out, true, rxc.fwPacket)
	if err != nil {
		hostinfo.logger(f.l).Warn("Error while validating inbound packet", "error", err, "packet", out)
		return
	}

	dropReason := f.firewall.Drop(rxc.fwPacket.Packet, true, hostinfo, f.pki.GetCAPool(), rxc.ctCache.Get())
	if dropReason != nil {
		// The reject rides the base tunnel: it is a control response, not lane
		// data, and the lane it arrived on says nothing about where it belongs.
		f.rejectOutside(out, hostinfo.ConnectionState, hostinfo, rxc.nb, rxc.scratch, rxc.q)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("dropping inbound packet", "fwPacket", rxc.fwPacket, "reason", dropReason)
		}
		return
	}

	err = f.batchers[rxc.q].Commit(out, batch.SortKey{Epoch: ci.epoch, Counter: messageCounter}, rxc.fwPacket)
	if err != nil {
		f.l.Error("Failed to write to tun", "error", err)
	}
}

func (f *Interface) maybeSendRecvError(endpoint netip.AddrPort, index uint32, q int) {
	if f.sendRecvErrorConfig.ShouldRecvError(endpoint) {
		f.sendRecvError(endpoint, index, q)
	}
}

// sendRecvError replies from the socket the offending packet arrived on (q).
// A lane peer's spoof guard compares our source addr against the lane's
// remote, so a reply from the base port would be discarded.
func (f *Interface) sendRecvError(endpoint netip.AddrPort, index uint32, q int) {
	f.messageMetrics.Tx(header.RecvError, 0, 1)

	b := header.Encode(make([]byte, header.Len), header.Version, header.RecvError, 0, index, 0)
	_ = f.writers[q].WriteTo(b, endpoint)
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

	hr := hostinfo.GetRemote()
	if hr.IsValid() && hr != addr {
		f.l.Info("Someone spoofing recv_errors?",
			"addr", addr,
			"hostinfoRemote", hr,
		)
		return
	}

	f.closeTunnel(hostinfo)
	// We also delete it from pending hostmap to allow for fast reconnect.
	f.handshakeManager.DeleteHostInfo(hostinfo)
}
