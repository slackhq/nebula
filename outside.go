package nebula

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv6"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"golang.org/x/net/ipv4"
)

const (
	minFwPacketLen = 4
)

func (f *Interface) readOutsidePackets(via ViaSender, out []byte, packet []byte, h *header.H, fwPacket *firewall.Packet, lhf *LightHouseHandler, nb []byte, q int, localCache firewall.ConntrackCache) {
	err := h.Parse(packet)
	if err != nil {
		// Hole punch packets are 0 or 1 byte big, so lets ignore printing those errors
		if len(packet) > 1 {
			f.l.WithField("packet", packet).Infof("Error while parsing inbound packet from %s: %s", via, err)
		}
		return
	}

	//l.Error("in packet ", header, packet[HeaderLen:])
	if !via.IsRelayed {
		if f.myVpnNetworksTable.Contains(via.UdpAddr.Addr()) {
			if f.l.Level >= logrus.DebugLevel {
				f.l.WithField("from", via).Debug("Refusing to process double encrypted packet")
			}
			return
		}
	}

	var hostinfo *HostInfo
	// verify if we've seen this index before, otherwise respond to the handshake initiation
	if h.Type == header.Message && h.Subtype == header.MessageRelay {
		hostinfo = f.hostMap.QueryRelayIndex(h.RemoteIndex)
	} else {
		hostinfo = f.hostMap.QueryIndex(h.RemoteIndex)
	}

	var ci *ConnectionState
	if hostinfo != nil {
		ci = hostinfo.ConnectionState
	}

	switch h.Type {
	case header.Message:
		if !f.handleEncrypted(ci, via, h) {
			return
		}

		switch h.Subtype {
		case header.MessageNone:
			if !f.decryptToTun(hostinfo, h.MessageCounter, out, packet, fwPacket, nb, q, localCache) {
				return
			}
		case header.MessageRelay:
			// The entire body is sent as AD, not encrypted.
			// The packet consists of a 16-byte parsed Nebula header, Associated Data-protected payload, and a trailing 16-byte AEAD signature value.
			// The packet is guaranteed to be at least 16 bytes at this point, b/c it got past the h.Parse() call above. If it's
			// otherwise malformed (meaning, there is no trailing 16 byte AEAD value), then this will result in at worst a 0-length slice
			// which will gracefully fail in the DecryptDanger call.
			signedPayload := packet[:len(packet)-hostinfo.ConnectionState.dKey.Overhead()]
			signatureValue := packet[len(packet)-hostinfo.ConnectionState.dKey.Overhead():]
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
				hostinfo.logger(f.l).WithFields(logrus.Fields{"vpnAddrs": hostinfo.vpnAddrs, "remoteIndex": h.RemoteIndex}).Error("HostInfo missing remote relay index")
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
				f.readOutsidePackets(via, out[:0], signedPayload, h, fwPacket, lhf, nb, q, localCache)
				return
			case ForwardingType:
				// Find the target HostInfo relay object
				targetHI, targetRelay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relay.PeerAddr)
				if err != nil {
					hostinfo.logger(f.l).WithField("relayTo", relay.PeerAddr).WithError(err).WithField("hostinfo.vpnAddrs", hostinfo.vpnAddrs).Info("Failed to find target host info by ip")
					return
				}

				// If that relay is Established, forward the payload through it
				if targetRelay.State == Established {
					switch targetRelay.Type {
					case ForwardingType:
						// Forward this packet through the relay tunnel
						// Find the target HostInfo
						f.SendVia(targetHI, targetRelay, signedPayload, nb, out, false)
						return
					case TerminalType:
						hostinfo.logger(f.l).Error("Unexpected Relay Type of Terminal")
					}
				} else {
					hostinfo.logger(f.l).WithFields(logrus.Fields{"relayTo": relay.PeerAddr, "relayFrom": hostinfo.vpnAddrs[0], "targetRelayState": targetRelay.State}).Info("Unexpected target relay state")
					return
				}
			}
		}

	case header.LightHouse:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		if !f.handleEncrypted(ci, via, h) {
			return
		}

		d, err := f.decrypt(hostinfo, h.MessageCounter, out, packet, h, nb)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).WithField("from", via).
				WithField("packet", packet).
				Error("Failed to decrypt lighthouse packet")
			return
		}

		//TODO: assert via is not relayed
		lhf.HandleRequest(via.UdpAddr, hostinfo.vpnAddrs, d, f)

		// Fallthrough to the bottom to record incoming traffic

	case header.Test:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		if !f.handleEncrypted(ci, via, h) {
			return
		}

		d, err := f.decrypt(hostinfo, h.MessageCounter, out, packet, h, nb)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).WithField("from", via).
				WithField("packet", packet).
				Error("Failed to decrypt test packet")
			return
		}

		if h.Subtype == header.TestRequest {
			// This testRequest might be from TryPromoteBest, so we should roam
			// to the new IP address before responding
			f.handleHostRoaming(hostinfo, via)
			f.send(header.Test, header.TestReply, ci, hostinfo, d, nb, out)
		}

		// Fallthrough to the bottom to record incoming traffic

		// Non encrypted messages below here, they should not fall through to avoid tracking incoming traffic since they
		// are unauthenticated

	case header.Handshake:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		f.handshakeManager.HandleIncoming(via, packet, h)
		return

	case header.RecvError:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		f.handleRecvError(via.UdpAddr, h)
		return

	case header.CloseTunnel:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		if !f.handleEncrypted(ci, via, h) {
			return
		}

		hostinfo.logger(f.l).WithField("from", via).
			Info("Close tunnel received, tearing down.")

		f.closeTunnel(hostinfo)
		return

	case header.Control:
		if !f.handleEncrypted(ci, via, h) {
			return
		}

		d, err := f.decrypt(hostinfo, h.MessageCounter, out, packet, h, nb)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).WithField("from", via).
				WithField("packet", packet).
				Error("Failed to decrypt Control packet")
			return
		}

		f.relayManager.HandleControlMsg(hostinfo, d, f)

	default:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		hostinfo.logger(f.l).Debugf("Unexpected packet received from %s", via)
		return
	}

	f.handleHostRoaming(hostinfo, via)

	f.connectionManager.In(hostinfo)
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
			hostinfo.logger(f.l).WithField("newAddr", via.UdpAddr).Debug("lighthouse.remote_allow_list denied roaming")
			return
		}

		if !hostinfo.lastRoam.IsZero() && via.UdpAddr == hostinfo.lastRoamRemote && time.Since(hostinfo.lastRoam) < RoamingSuppressSeconds*time.Second {
			if f.l.Level >= logrus.DebugLevel {
				hostinfo.logger(f.l).WithField("udpAddr", hostinfo.remote).WithField("newAddr", via.UdpAddr).
					Debugf("Suppressing roam back to previous remote for %d seconds", RoamingSuppressSeconds)
			}
			return
		}

		hostinfo.logger(f.l).WithField("udpAddr", hostinfo.remote).WithField("newAddr", via.UdpAddr).
			Info("Host roamed to new udp ip/port.")
		hostinfo.lastRoam = time.Now()
		hostinfo.lastRoamRemote = hostinfo.remote
		hostinfo.SetRemote(via.UdpAddr)
	}

}

// handleEncrypted returns true if a packet should be processed, false otherwise
func (f *Interface) handleEncrypted(ci *ConnectionState, via ViaSender, h *header.H) bool {
	// If connectionstate does not exist, send a recv error, if possible, to encourage a fast reconnect
	if ci == nil {
		if !via.IsRelayed {
			f.maybeSendRecvError(via.UdpAddr, h.RemoteIndex)
		}
		return false
	}
	// If the window check fails, refuse to process the packet, but don't send a recv error
	if !ci.window.Check(f.l, h.MessageCounter) {
		return false
	}

	return true
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
func newPacket(data []byte, incoming bool, fp *firewall.Packet) error {
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

func parseV6(data []byte, incoming bool, fp *firewall.Packet) error {
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

	protoAt := 6             // NextHeader is at 6 bytes into the ipv6 header
	offset := ipv6.HeaderLen // Start at the end of the ipv6 header
	next := 0
	for {
		if protoAt >= dataLen {
			break
		}
		proto := layers.IPProtocol(data[protoAt])

		switch proto {
		case layers.IPProtocolICMPv6, layers.IPProtocolESP, layers.IPProtocolNoNextHeader:
			fp.Protocol = uint8(proto)
			fp.RemotePort = 0
			fp.LocalPort = 0
			fp.Fragment = false
			return nil

		case layers.IPProtocolTCP, layers.IPProtocolUDP:
			if dataLen < offset+4 {
				return ErrIPv6PacketTooShort
			}

			fp.Protocol = uint8(proto)
			if incoming {
				fp.RemotePort = binary.BigEndian.Uint16(data[offset : offset+2])
				fp.LocalPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			} else {
				fp.LocalPort = binary.BigEndian.Uint16(data[offset : offset+2])
				fp.RemotePort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			}

			fp.Fragment = false
			return nil

		case layers.IPProtocolIPv6Fragment:
			// Fragment header is 8 bytes, need at least offset+4 to read the offset field
			if dataLen < offset+8 {
				return ErrIPv6PacketTooShort
			}

			// Check if this is the first fragment
			fragmentOffset := binary.BigEndian.Uint16(data[offset+2:offset+4]) &^ uint16(0x7) // Remove the reserved and M flag bits
			if fragmentOffset != 0 {
				// Non-first fragment, use what we have now and stop processing
				fp.Protocol = data[offset]
				fp.Fragment = true
				fp.RemotePort = 0
				fp.LocalPort = 0
				return nil
			}

			// The next loop should be the transport layer since we are the first fragment
			next = 8 // Fragment headers are always 8 bytes

		case layers.IPProtocolAH:
			// Auth headers, used by IPSec, have a different meaning for header length
			if dataLen <= offset+1 {
				break
			}

			next = int(data[offset+1]+2) << 2

		default:
			// Normal ipv6 header length processing
			if dataLen <= offset+1 {
				break
			}

			next = int(data[offset+1]+1) << 3
		}

		if next <= 0 {
			// Safety check, each ipv6 header has to be at least 8 bytes
			next = 8
		}

		protoAt = offset
		offset = offset + next
	}

	return ErrIPv6CouldNotFindPayload
}

func parseV4(data []byte, incoming bool, fp *firewall.Packet) error {
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

	// Firewall handles protocol checks
	fp.Protocol = data[9]

	// Accounting for a variable header length, do we have enough data for our src/dst tuples?
	minLen := ihl
	if !fp.Fragment && fp.Protocol != firewall.ProtoICMP {
		minLen += minFwPacketLen
	}
	if len(data) < minLen {
		return ErrIPv4InvalidHeaderLength
	}

	// Firewall packets are locally oriented
	if incoming {
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[12:16])
		fp.LocalAddr, _ = netip.AddrFromSlice(data[16:20])
		if fp.Fragment || fp.Protocol == firewall.ProtoICMP {
			fp.RemotePort = 0
			fp.LocalPort = 0
		} else {
			fp.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			fp.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	} else {
		fp.LocalAddr, _ = netip.AddrFromSlice(data[12:16])
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[16:20])
		if fp.Fragment || fp.Protocol == firewall.ProtoICMP {
			fp.RemotePort = 0
			fp.LocalPort = 0
		} else {
			fp.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			fp.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	}

	return nil
}

func (f *Interface) decrypt(hostinfo *HostInfo, mc uint64, out []byte, packet []byte, h *header.H, nb []byte) ([]byte, error) {
	var err error
	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, packet[:header.Len], packet[header.Len:], mc, nb)
	if err != nil {
		return nil, err
	}

	if !hostinfo.ConnectionState.window.Update(f.l, mc) {
		hostinfo.logger(f.l).WithField("header", h).
			Debugln("dropping out of window packet")
		return nil, errors.New("out of window packet")
	}

	return out, nil
}

func (f *Interface) decryptToTun(hostinfo *HostInfo, messageCounter uint64, out []byte, packet []byte, fwPacket *firewall.Packet, nb []byte, q int, localCache firewall.ConntrackCache) bool {
	var err error

	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, packet[:header.Len], packet[header.Len:], messageCounter, nb)
	if err != nil {
		hostinfo.logger(f.l).WithError(err).Error("Failed to decrypt packet")
		return false
	}

	err = newPacket(out, true, fwPacket)
	if err != nil {
		hostinfo.logger(f.l).WithError(err).WithField("packet", out).
			Warnf("Error while validating inbound packet")
		return false
	}

	if !hostinfo.ConnectionState.window.Update(f.l, messageCounter) {
		hostinfo.logger(f.l).WithField("fwPacket", fwPacket).
			Debugln("dropping out of window packet")
		return false
	}

	dropReason := f.firewall.Drop(*fwPacket, true, hostinfo, f.pki.GetCAPool(), localCache)
	if dropReason != nil {
		// NOTE: We give `packet` as the `out` here since we already decrypted from it and we don't need it anymore
		// This gives us a buffer to build the reject packet in
		f.rejectOutside(out, hostinfo.ConnectionState, hostinfo, nb, packet, q)
		if f.l.Level >= logrus.DebugLevel {
			hostinfo.logger(f.l).WithField("fwPacket", fwPacket).
				WithField("reason", dropReason).
				Debugln("dropping inbound packet")
		}
		return false
	}

	f.connectionManager.In(hostinfo)
	_, err = f.readers[q].Write(out)
	if err != nil {
		f.l.WithError(err).Error("Failed to write to tun")
	}
	return true
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
	if f.l.Level >= logrus.DebugLevel {
		f.l.WithField("index", index).
			WithField("udpAddr", endpoint).
			Debug("Recv error sent")
	}
}

func (f *Interface) handleRecvError(addr netip.AddrPort, h *header.H) {
	if !f.acceptRecvErrorConfig.ShouldRecvError(addr) {
		f.l.WithField("index", h.RemoteIndex).
			WithField("udpAddr", addr).
			Debug("Recv error received, ignoring")
		return
	}

	if f.l.Level >= logrus.DebugLevel {
		f.l.WithField("index", h.RemoteIndex).
			WithField("udpAddr", addr).
			Debug("Recv error received")
	}

	hostinfo := f.hostMap.QueryReverseIndex(h.RemoteIndex)
	if hostinfo == nil {
		f.l.WithField("remoteIndex", h.RemoteIndex).Debugln("Did not find remote index in main hostmap")
		return
	}

	if hostinfo.remote.IsValid() && hostinfo.remote != addr {
		f.l.Infoln("Someone spoofing recv_errors? ", addr, hostinfo.remote)
		return
	}

	f.closeTunnel(hostinfo)
	// We also delete it from pending hostmap to allow for fast reconnect.
	f.handshakeManager.DeleteHostInfo(hostinfo)
}
