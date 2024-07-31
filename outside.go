package nebula

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
	"golang.org/x/net/ipv4"
	"google.golang.org/protobuf/proto"
)

const (
	minFwPacketLen = 4
)

// TODO: IPV6-WORK this can likely be removed now
func readOutsidePackets(f *Interface) udp.EncReader {
	return func(
		addr netip.AddrPort,
		out []byte,
		packet []byte,
		header *header.H,
		fwPacket *firewall.Packet,
		lhh udp.LightHouseHandlerFunc,
		nb []byte,
		q int,
		localCache firewall.ConntrackCache,
	) {
		f.readOutsidePackets(addr, nil, out, packet, header, fwPacket, lhh, nb, q, localCache)
	}
}

func (f *Interface) readOutsidePackets(ip netip.AddrPort, via *ViaSender, out []byte, packet []byte, h *header.H, fwPacket *firewall.Packet, lhf udp.LightHouseHandlerFunc, nb []byte, q int, localCache firewall.ConntrackCache) {
	err := h.Parse(packet)
	if err != nil {
		// TODO: best if we return this and let caller log
		// TODO: Might be better to send the literal []byte("holepunch") packet and ignore that?
		// Hole punch packets are 0 or 1 byte big, so lets ignore printing those errors
		if len(packet) > 1 {
			f.l.WithField("packet", packet).Infof("Error while parsing inbound packet from %s: %s", ip, err)
		}
		return
	}

	//l.Error("in packet ", header, packet[HeaderLen:])
	if ip.IsValid() {
		if f.myVpnNet.Contains(ip.Addr()) {
			if f.l.Level >= logrus.DebugLevel {
				f.l.WithField("udpAddr", ip).Debug("Refusing to process double encrypted packet")
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
		// TODO handleEncrypted sends directly to addr on error. Handle this in the tunneling case.
		if !f.handleEncrypted(ci, ip, h) {
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
			f.handleHostRoaming(hostinfo, ip)
			// Track usage of both the HostInfo and the Relay for the received & authenticated packet
			f.connectionManager.In(hostinfo.localIndexId)
			f.connectionManager.RelayUsed(h.RemoteIndex)

			relay, ok := hostinfo.relayState.QueryRelayForByIdx(h.RemoteIndex)
			if !ok {
				// The only way this happens is if hostmap has an index to the correct HostInfo, but the HostInfo is missing
				// its internal mapping. This should never happen.
				hostinfo.logger(f.l).WithFields(logrus.Fields{"vpnIp": hostinfo.vpnIp, "remoteIndex": h.RemoteIndex}).Error("HostInfo missing remote relay index")
				return
			}

			switch relay.Type {
			case TerminalType:
				// If I am the target of this relay, process the unwrapped packet
				// From this recursive point, all these variables are 'burned'. We shouldn't rely on them again.
				f.readOutsidePackets(netip.AddrPort{}, &ViaSender{relayHI: hostinfo, remoteIdx: relay.RemoteIndex, relay: relay}, out[:0], signedPayload, h, fwPacket, lhf, nb, q, localCache)
				return
			case ForwardingType:
				// Find the target HostInfo relay object
				targetHI, targetRelay, err := f.hostMap.QueryVpnIpRelayFor(hostinfo.vpnIp, relay.PeerIp)
				if err != nil {
					hostinfo.logger(f.l).WithField("relayTo", relay.PeerIp).WithError(err).Info("Failed to find target host info by ip")
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
					hostinfo.logger(f.l).WithFields(logrus.Fields{"relayTo": relay.PeerIp, "relayFrom": hostinfo.vpnIp, "targetRelayState": targetRelay.State}).Info("Unexpected target relay state")
					return
				}
			}
		}

	case header.LightHouse:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		if !f.handleEncrypted(ci, ip, h) {
			return
		}

		d, err := f.decrypt(hostinfo, h.MessageCounter, out, packet, h, nb)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).WithField("udpAddr", ip).
				WithField("packet", packet).
				Error("Failed to decrypt lighthouse packet")

			//TODO: maybe after build 64 is out? 06/14/2018 - NB
			//f.sendRecvError(net.Addr(addr), header.RemoteIndex)
			return
		}

		lhf(ip, hostinfo.vpnIp, d)

		// Fallthrough to the bottom to record incoming traffic

	case header.Test:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		if !f.handleEncrypted(ci, ip, h) {
			return
		}

		d, err := f.decrypt(hostinfo, h.MessageCounter, out, packet, h, nb)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).WithField("udpAddr", ip).
				WithField("packet", packet).
				Error("Failed to decrypt test packet")

			//TODO: maybe after build 64 is out? 06/14/2018 - NB
			//f.sendRecvError(net.Addr(addr), header.RemoteIndex)
			return
		}

		if h.Subtype == header.TestRequest {
			// This testRequest might be from TryPromoteBest, so we should roam
			// to the new IP address before responding
			f.handleHostRoaming(hostinfo, ip)
			f.send(header.Test, header.TestReply, ci, hostinfo, d, nb, out)
		}

		// Fallthrough to the bottom to record incoming traffic

		// Non encrypted messages below here, they should not fall through to avoid tracking incoming traffic since they
		// are unauthenticated

	case header.Handshake:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		f.handshakeManager.HandleIncoming(ip, via, packet, h)
		return

	case header.RecvError:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		f.handleRecvError(ip, h)
		return

	case header.CloseTunnel:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		if !f.handleEncrypted(ci, ip, h) {
			return
		}

		hostinfo.logger(f.l).WithField("udpAddr", ip).
			Info("Close tunnel received, tearing down.")

		f.closeTunnel(hostinfo)
		return

	case header.Control:
		if !f.handleEncrypted(ci, ip, h) {
			return
		}

		d, err := f.decrypt(hostinfo, h.MessageCounter, out, packet, h, nb)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).WithField("udpAddr", ip).
				WithField("packet", packet).
				Error("Failed to decrypt Control packet")
			return
		}
		m := &NebulaControl{}
		err = m.Unmarshal(d)
		if err != nil {
			hostinfo.logger(f.l).WithError(err).Error("Failed to unmarshal control message")
			break
		}

		f.relayManager.HandleControlMsg(hostinfo, m, f)

	default:
		f.messageMetrics.Rx(h.Type, h.Subtype, 1)
		hostinfo.logger(f.l).Debugf("Unexpected packet received from %s", ip)
		return
	}

	f.handleHostRoaming(hostinfo, ip)

	f.connectionManager.In(hostinfo.localIndexId)
}

// closeTunnel closes a tunnel locally, it does not send a closeTunnel packet to the remote
func (f *Interface) closeTunnel(hostInfo *HostInfo) {
	final := f.hostMap.DeleteHostInfo(hostInfo)
	if final {
		// We no longer have any tunnels with this vpn ip, clear learned lighthouse state to lower memory usage
		f.lightHouse.DeleteVpnIp(hostInfo.vpnIp)
	}
}

// sendCloseTunnel is a helper function to send a proper close tunnel packet to a remote
func (f *Interface) sendCloseTunnel(h *HostInfo) {
	f.send(header.CloseTunnel, 0, h.ConnectionState, h, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
}

func (f *Interface) handleHostRoaming(hostinfo *HostInfo, ip netip.AddrPort) {
	if ip.IsValid() && hostinfo.remote != ip {
		if !f.lightHouse.GetRemoteAllowList().Allow(hostinfo.vpnIp, ip.Addr()) {
			hostinfo.logger(f.l).WithField("newAddr", ip).Debug("lighthouse.remote_allow_list denied roaming")
			return
		}
		if !hostinfo.lastRoam.IsZero() && ip == hostinfo.lastRoamRemote && time.Since(hostinfo.lastRoam) < RoamingSuppressSeconds*time.Second {
			if f.l.Level >= logrus.DebugLevel {
				hostinfo.logger(f.l).WithField("udpAddr", hostinfo.remote).WithField("newAddr", ip).
					Debugf("Suppressing roam back to previous remote for %d seconds", RoamingSuppressSeconds)
			}
			return
		}

		hostinfo.logger(f.l).WithField("udpAddr", hostinfo.remote).WithField("newAddr", ip).
			Info("Host roamed to new udp ip/port.")
		hostinfo.lastRoam = time.Now()
		hostinfo.lastRoamRemote = hostinfo.remote
		hostinfo.SetRemote(ip)
	}

}

func (f *Interface) handleEncrypted(ci *ConnectionState, addr netip.AddrPort, h *header.H) bool {
	// If connectionstate exists and the replay protector allows, process packet
	// Else, send recv errors for 300 seconds after a restart to allow fast reconnection.
	if ci == nil || !ci.window.Check(f.l, h.MessageCounter) {
		if addr.IsValid() {
			f.maybeSendRecvError(addr, h.RemoteIndex)
			return false
		} else {
			return false
		}
	}

	return true
}

// newPacket validates and parses the interesting bits for the firewall out of the ip and sub protocol headers
func newPacket(data []byte, incoming bool, fp *firewall.Packet) error {
	// Do we at least have an ipv4 header worth of data?
	if len(data) < ipv4.HeaderLen {
		return fmt.Errorf("packet is less than %v bytes", ipv4.HeaderLen)
	}

	// Is it an ipv4 packet?
	if int((data[0]>>4)&0x0f) != 4 {
		return fmt.Errorf("packet is not ipv4, type: %v", int((data[0]>>4)&0x0f))
	}

	// Adjust our start position based on the advertised ip header length
	ihl := int(data[0]&0x0f) << 2

	// Well formed ip header length?
	if ihl < ipv4.HeaderLen {
		return fmt.Errorf("packet had an invalid header length: %v", ihl)
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
		return fmt.Errorf("packet is less than %v bytes, ip header len: %v", minLen, ihl)
	}

	// Firewall packets are locally oriented
	if incoming {
		//TODO: IPV6-WORK
		fp.RemoteIP, _ = netip.AddrFromSlice(data[12:16])
		fp.LocalIP, _ = netip.AddrFromSlice(data[16:20])
		if fp.Fragment || fp.Protocol == firewall.ProtoICMP {
			fp.RemotePort = 0
			fp.LocalPort = 0
		} else {
			fp.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			fp.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	} else {
		//TODO: IPV6-WORK
		fp.LocalIP, _ = netip.AddrFromSlice(data[12:16])
		fp.RemoteIP, _ = netip.AddrFromSlice(data[16:20])
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
		//TODO: maybe after build 64 is out? 06/14/2018 - NB
		//f.sendRecvError(hostinfo.remote, header.RemoteIndex)
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

	f.connectionManager.In(hostinfo.localIndexId)
	_, err = f.readers[q].Write(out)
	if err != nil {
		f.l.WithError(err).Error("Failed to write to tun")
	}
	return true
}

func (f *Interface) maybeSendRecvError(endpoint netip.AddrPort, index uint32) {
	if f.sendRecvErrorConfig.ShouldSendRecvError(endpoint) {
		f.sendRecvError(endpoint, index)
	}
}

func (f *Interface) sendRecvError(endpoint netip.AddrPort, index uint32) {
	f.messageMetrics.Tx(header.RecvError, 0, 1)

	//TODO: this should be a signed message so we can trust that we should drop the index
	b := header.Encode(make([]byte, header.Len), header.Version, header.RecvError, 0, index, 0)
	f.outside.WriteTo(b, endpoint)
	if f.l.Level >= logrus.DebugLevel {
		f.l.WithField("index", index).
			WithField("udpAddr", endpoint).
			Debug("Recv error sent")
	}
}

func (f *Interface) handleRecvError(addr netip.AddrPort, h *header.H) {
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

	if !hostinfo.RecvErrorExceeded() {
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

/*
func (f *Interface) sendMeta(ci *ConnectionState, endpoint *net.UDPAddr, meta *NebulaMeta) {
	if ci.eKey != nil {
		//TODO: log error?
		return
	}

	msg, err := proto.Marshal(meta)
	if err != nil {
		l.Debugln("failed to encode header")
	}

	c := ci.messageCounter
	b := HeaderEncode(nil, Version, uint8(metadata), 0, hostinfo.remoteIndexId, c)
	ci.messageCounter++

	msg := ci.eKey.EncryptDanger(b, nil, msg, c)
	//msg := ci.eKey.EncryptDanger(b, nil, []byte(fmt.Sprintf("%d", counter)), c)
	f.outside.WriteTo(msg, endpoint)
}
*/

func RecombineCertAndValidate(h *noise.HandshakeState, rawCertBytes []byte, caPool *cert.NebulaCAPool) (*cert.NebulaCertificate, error) {
	pk := h.PeerStatic()

	if pk == nil {
		return nil, errors.New("no peer static key was present")
	}

	if rawCertBytes == nil {
		return nil, errors.New("provided payload was empty")
	}

	r := &cert.RawNebulaCertificate{}
	err := proto.Unmarshal(rawCertBytes, r)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling cert: %s", err)
	}

	// If the Details are nil, just exit to avoid crashing
	if r.Details == nil {
		return nil, fmt.Errorf("certificate did not contain any details")
	}

	r.Details.PublicKey = pk
	recombined, err := proto.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("error while recombining certificate: %s", err)
	}

	c, _ := cert.UnmarshalNebulaCertificate(recombined)
	isValid, err := c.Verify(time.Now(), caPool)
	if err != nil {
		return c, fmt.Errorf("certificate validation failed: %s", err)
	} else if !isValid {
		// This case should never happen but here's to defensive programming!
		return c, errors.New("certificate validation failed but did not return an error")
	}

	return c, nil
}
