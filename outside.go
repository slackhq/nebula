package nebula

import (
	"encoding/binary"

	"github.com/flynn/noise"
	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	// "github.com/google/gopacket"
	// "github.com/google/gopacket/layers"
	// 	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	minFwPacketLen = 4
)

func (f *Interface) readOutsidePackets(addr *udpAddr, out []byte, packet []byte, header *Header, fwPacket *FirewallPacket, nb []byte) {
	err := header.Parse(packet)
	if err != nil {
		// TODO: best if we return this and let caller log
		// TODO: Might be better to send the literal []byte("holepunch") packet and ignore that?
		// Hole punch packets are 0 or 1 byte big, so lets ignore printing those errors
		if len(packet) > 1 {
			l.WithField("packet", packet).Infof("Error while parsing inbound packet from %s: %s", addr, err)
		}
		return
	}

	//l.Error("in packet ", header, packet[HeaderLen:])

	// verify if we've seen this index before, otherwise respond to the handshake initiation
	hostinfo, err := f.hostMap.QueryIndex(header.RemoteIndex)

	var ci *ConnectionState
	if err == nil {
		ci = hostinfo.ConnectionState
	}

	switch header.Type {
	case message:
		if !f.handleEncrypted(ci, addr, header) {
			return
		}

		f.decryptToTun(hostinfo, header.MessageCounter, out, packet, fwPacket, nb)

		// Fallthrough to the bottom to record incoming traffic

	case lightHouse:
		if !f.handleEncrypted(ci, addr, header) {
			return
		}

		d, err := f.decrypt(hostinfo, header.MessageCounter, out, packet, header, nb)
		if err != nil {
			hostinfo.logger().WithError(err).WithField("udpAddr", addr).
				WithField("packet", packet).
				Error("Failed to decrypt lighthouse packet")

			//TODO: maybe after build 64 is out? 06/14/2018 - NB
			//f.sendRecvError(net.Addr(addr), header.RemoteIndex)
			return
		}

		f.lightHouse.HandleRequest(addr, hostinfo.hostId, d, hostinfo.GetCert(), f)

		// Fallthrough to the bottom to record incoming traffic

	case test:
		if !f.handleEncrypted(ci, addr, header) {
			return
		}

		d, err := f.decrypt(hostinfo, header.MessageCounter, out, packet, header, nb)
		if err != nil {
			hostinfo.logger().WithError(err).WithField("udpAddr", addr).
				WithField("packet", packet).
				Error("Failed to decrypt test packet")

			//TODO: maybe after build 64 is out? 06/14/2018 - NB
			//f.sendRecvError(net.Addr(addr), header.RemoteIndex)
			return
		}

		if header.Subtype == testRequest {
			// This testRequest might be from TryPromoteBest, so we should roam
			// to the new IP address before responding
			f.handleHostRoaming(hostinfo, addr)
			f.send(test, testReply, ci, hostinfo, hostinfo.remote, d, nb, out)
		}

		// Fallthrough to the bottom to record incoming traffic

		// Non encrypted messages below here, they should not fall through to avoid tracking incoming traffic since they
		// are unauthenticated

	case handshake:
		HandleIncomingHandshake(f, addr, packet, header, hostinfo)
		return

	case recvError:
		// TODO: Remove this with recv_error deprecation
		f.handleRecvError(addr, header)
		return

	case closeTunnel:
		if !f.handleEncrypted(ci, addr, header) {
			return
		}

		hostinfo.logger().WithField("udpAddr", addr).
			Info("Close tunnel received, tearing down.")

		f.closeTunnel(hostinfo)
		return

	default:
		hostinfo.logger().Debugf("Unexpected packet received from %s", addr)
		return
	}

	f.handleHostRoaming(hostinfo, addr)

	f.connectionManager.In(hostinfo.hostId)
}

func (f *Interface) closeTunnel(hostInfo *HostInfo) {
	//TODO: this would be better as a single function in ConnectionManager that handled locks appropriately
	f.connectionManager.ClearIP(hostInfo.hostId)
	f.connectionManager.ClearPendingDeletion(hostInfo.hostId)
	f.lightHouse.DeleteVpnIP(hostInfo.hostId)
	f.hostMap.DeleteVpnIP(hostInfo.hostId)
	f.hostMap.DeleteIndex(hostInfo.localIndexId)
}

func (f *Interface) handleHostRoaming(hostinfo *HostInfo, addr *udpAddr) {
	if hostDidRoam(hostinfo.remote, addr) {
		if !f.lightHouse.remoteAllowList.Allow(udp2ipInt(addr)) {
			hostinfo.logger().WithField("newAddr", addr).Debug("lighthouse.remote_allow_list denied roaming")
			return
		}
		if !hostinfo.lastRoam.IsZero() && addr.Equals(hostinfo.lastRoamRemote) && time.Since(hostinfo.lastRoam) < RoamingSupressSeconds*time.Second {
			if l.Level >= logrus.DebugLevel {
				hostinfo.logger().WithField("udpAddr", hostinfo.remote).WithField("newAddr", addr).
					Debugf("Supressing roam back to previous remote for %d seconds", RoamingSupressSeconds)
			}
			return
		}

		hostinfo.logger().WithField("udpAddr", hostinfo.remote).WithField("newAddr", addr).
			Info("Host roamed to new udp ip/port.")
		hostinfo.lastRoam = time.Now()
		remoteCopy := *hostinfo.remote
		hostinfo.lastRoamRemote = &remoteCopy
		hostinfo.SetRemote(*addr)
		if f.lightHouse.amLighthouse {
			f.lightHouse.AddRemote(hostinfo.hostId, addr, false)
		}
	}

}

func (f *Interface) handleEncrypted(ci *ConnectionState, addr *udpAddr, header *Header) bool {
	// If connectionstate exists and the replay protector allows, process packet
	// Else, send recv errors for 300 seconds after a restart to allow fast reconnection.
	if ci == nil || !ci.window.Check(header.MessageCounter) {
		f.sendRecvError(addr, header.RemoteIndex)
		return false
	}

	return true
}

// newPacket validates and parses the interesting bits for the firewall out of the ip and sub protocol headers
func newPacket(data []byte, incoming bool, fp *FirewallPacket) error {
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
	if !fp.Fragment && fp.Protocol != fwProtoICMP {
		minLen += minFwPacketLen
	}
	if len(data) < minLen {
		return fmt.Errorf("packet is less than %v bytes, ip header len: %v", minLen, ihl)
	}

	// Firewall packets are locally oriented
	if incoming {
		fp.RemoteIP = binary.BigEndian.Uint32(data[12:16])
		fp.LocalIP = binary.BigEndian.Uint32(data[16:20])
		if fp.Fragment || fp.Protocol == fwProtoICMP {
			fp.RemotePort = 0
			fp.LocalPort = 0
		} else {
			fp.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			fp.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	} else {
		fp.LocalIP = binary.BigEndian.Uint32(data[12:16])
		fp.RemoteIP = binary.BigEndian.Uint32(data[16:20])
		if fp.Fragment || fp.Protocol == fwProtoICMP {
			fp.RemotePort = 0
			fp.LocalPort = 0
		} else {
			fp.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			fp.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	}

	return nil
}

func (f *Interface) decrypt(hostinfo *HostInfo, mc uint64, out []byte, packet []byte, header *Header, nb []byte) ([]byte, error) {
	var err error
	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, packet[:HeaderLen], packet[HeaderLen:], mc, nb)
	if err != nil {
		return nil, err
	}

	if !hostinfo.ConnectionState.window.Update(mc) {
		hostinfo.logger().WithField("header", header).
			Debugln("dropping out of window packet")
		return nil, errors.New("out of window packet")
	}

	return out, nil
}

func (f *Interface) decryptToTun(hostinfo *HostInfo, messageCounter uint64, out []byte, packet []byte, fwPacket *FirewallPacket, nb []byte) {
	var err error

	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, packet[:HeaderLen], packet[HeaderLen:], messageCounter, nb)
	if err != nil {
		hostinfo.logger().WithError(err).Error("Failed to decrypt packet")
		//TODO: maybe after build 64 is out? 06/14/2018 - NB
		//f.sendRecvError(hostinfo.remote, header.RemoteIndex)
		return
	}

	err = newPacket(out, true, fwPacket)
	if err != nil {
		hostinfo.logger().WithError(err).WithField("packet", out).
			Warnf("Error while validating inbound packet")
		return
	}

	if !hostinfo.ConnectionState.window.Update(messageCounter) {
		hostinfo.logger().WithField("fwPacket", fwPacket).
			Debugln("dropping out of window packet")
		return
	}

	if f.firewall.Drop(out, *fwPacket, true, hostinfo, trustedCAs) {
		hostinfo.logger().WithField("fwPacket", fwPacket).
			Debugln("dropping inbound packet")
		return
	}

	f.connectionManager.In(hostinfo.hostId)
	err = f.inside.WriteRaw(out)
	if err != nil {
		l.WithError(err).Error("Failed to write to tun")
	}
}

func (f *Interface) sendRecvError(endpoint *udpAddr, index uint32) {
	f.metricTxRecvError.Inc(1)

	//TODO: this should be a signed message so we can trust that we should drop the index
	b := HeaderEncode(make([]byte, HeaderLen), Version, uint8(recvError), 0, index, 0)
	f.outside.WriteTo(b, endpoint)
	if l.Level >= logrus.DebugLevel {
		l.WithField("index", index).
			WithField("udpAddr", endpoint).
			Debug("Recv error sent")
	}
}

func (f *Interface) handleRecvError(addr *udpAddr, h *Header) {
	f.metricRxRecvError.Inc(1)

	// This flag is to stop caring about recv_error from old versions
	// This should go away when the old version is gone from prod
	if l.Level >= logrus.DebugLevel {
		l.WithField("index", h.RemoteIndex).
			WithField("udpAddr", addr).
			Debug("Recv error received")
	}

	hostinfo, err := f.hostMap.QueryReverseIndex(h.RemoteIndex)
	if err != nil {
		l.Debugln(err, ": ", h.RemoteIndex)
		return
	}

	if !hostinfo.RecvErrorExceeded() {
		return
	}
	if hostinfo.remote != nil && hostinfo.remote.String() != addr.String() {
		l.Infoln("Someone spoofing recv_errors? ", addr, hostinfo.remote)
		return
	}

	id := hostinfo.localIndexId
	host := hostinfo.hostId
	// We delete this host from the main hostmap
	f.hostMap.DeleteIndex(id)
	f.hostMap.DeleteVpnIP(host)
	// We also delete it from pending to allow for
	// fast reconnect. We must null the connectionstate
	// or a counter reuse may happen
	hostinfo.ConnectionState = nil
	f.handshakeManager.DeleteIndex(id)
	f.handshakeManager.DeleteVpnIP(host)
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

func RecombineCertAndValidate(h *noise.HandshakeState, rawCertBytes []byte) (*cert.NebulaCertificate, error) {
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
	isValid, err := c.Verify(time.Now(), trustedCAs)
	if err != nil {
		return c, fmt.Errorf("certificate validation failed: %s", err)
	} else if !isValid {
		// This case should never happen but here's to defensive programming!
		return c, errors.New("certificate validation failed but did not return an error")
	}

	return c, nil
}
