package nebula

import (
	"bytes"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/golang/protobuf/proto"
)

// NOISE IX Handshakes

// This function constructs a handshake packet, but does not actually send it
// Sending is done by the handshake manager
func ixHandshakeStage0(f *Interface, vpnIp uint32, hostinfo *HostInfo) {
	// This queries the lighthouse if we don't know a remote for the host
	if hostinfo.remote == nil {
		ips, err := f.lightHouse.Query(vpnIp, f)
		if err != nil {
			//l.Debugln(err)
		}
		for _, ip := range ips {
			hostinfo.AddRemote(ip)
		}
	}

	err := f.handshakeManager.AddIndexHostInfo(hostinfo)
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to generate index")
		return
	}

	ci := hostinfo.ConnectionState

	hsProto := &NebulaHandshakeDetails{
		InitiatorIndex: hostinfo.localIndexId,
		Time:           uint64(time.Now().Unix()),
		Cert:           ci.certState.rawCertificateNoKey,
	}

	hsBytes := []byte{}

	hs := &NebulaHandshake{
		Details: hsProto,
	}
	hsBytes, err = proto.Marshal(hs)

	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to marshal handshake message")
		return
	}

	header := HeaderEncode(make([]byte, HeaderLen), Version, uint8(handshake), handshakeIXPSK0, 0, 1)
	atomic.AddUint64(&ci.atomicMessageCounter, 1)

	msg, _, _, err := ci.H.WriteMessage(header, hsBytes)
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to call noise.WriteMessage")
		return
	}

	// We are sending handshake packet 1, so we don't expect to receive
	// handshake packet 1 from the responder
	ci.window.Update(1)

	hostinfo.HandshakePacket[0] = msg
	hostinfo.HandshakeReady = true
	hostinfo.handshakeStart = time.Now()

}

func ixHandshakeStage1(f *Interface, addr *udpAddr, packet []byte, h *Header) {
	ci := f.newConnectionState(false, noise.HandshakeIX, []byte{}, 0)
	// Mark packet 1 as seen so it doesn't show up as missed
	ci.window.Update(1)

	msg, _, _, err := ci.H.ReadMessage(nil, packet[HeaderLen:])
	if err != nil {
		l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to call noise.ReadMessage")
		return
	}

	hs := &NebulaHandshake{}
	err = proto.Unmarshal(msg, hs)
	/*
		l.Debugln("GOT INDEX: ", hs.Details.InitiatorIndex)
	*/
	if err != nil || hs.Details == nil {
		l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed unmarshal handshake message")
		return
	}

	remoteCert, err := RecombineCertAndValidate(ci.H, hs.Details.Cert)
	if err != nil {
		l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).WithField("cert", remoteCert).
			Info("Invalid certificate from host")
		return
	}
	vpnIP := ip2int(remoteCert.Details.Ips[0].IP)
	certName := remoteCert.Details.Name
	fingerprint, _ := remoteCert.Sha256Sum()

	if vpnIP == ip2int(f.certState.certificate.Details.Ips[0].IP) {
		l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Refusing to handshake with myself")
		return
	}

	myIndex, err := generateIndex()
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to generate index")
		return
	}

	hostinfo := &HostInfo{
		ConnectionState: ci,
		Remotes:         []*HostInfoDest{},
		localIndexId:    myIndex,
		remoteIndexId:   hs.Details.InitiatorIndex,
		hostId:          vpnIP,
		HandshakePacket: make(map[uint8][]byte, 0),
	}

	l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
		WithField("certName", certName).
		WithField("fingerprint", fingerprint).
		WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
		WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
		Info("Handshake message received")

	hs.Details.ResponderIndex = myIndex
	hs.Details.Cert = ci.certState.rawCertificateNoKey

	hsBytes, err := proto.Marshal(hs)
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to marshal handshake message")
		return
	}

	header := HeaderEncode(make([]byte, HeaderLen), Version, uint8(handshake), handshakeIXPSK0, hs.Details.InitiatorIndex, 2)
	msg, dKey, eKey, err := ci.H.WriteMessage(header, hsBytes)
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to call noise.WriteMessage")
		return
	} else if dKey == nil || eKey == nil {
		l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Noise did not arrive at a key")
		return
	}

	hostinfo.HandshakePacket[0] = make([]byte, len(packet[HeaderLen:]))
	copy(hostinfo.HandshakePacket[0], packet[HeaderLen:])

	// Regardless of whether you are the sender or receiver, you should arrive here
	// and complete standing up the connection.
	hostinfo.HandshakePacket[2] = make([]byte, len(msg))
	copy(hostinfo.HandshakePacket[2], msg)

	// We are sending handshake packet 2, so we don't expect to receive
	// handshake packet 2 from the initiator.
	ci.window.Update(2)

	ci.peerCert = remoteCert
	ci.dKey = NewNebulaCipherState(dKey)
	ci.eKey = NewNebulaCipherState(eKey)
	//l.Debugln("got symmetric pairs")

	//hostinfo.ClearRemotes()
	hostinfo.AddRemote(addr)
	hostinfo.ForcePromoteBest(f.hostMap.preferredRanges)
	hostinfo.CreateRemoteCIDR(remoteCert)

	hostinfo.Lock()
	defer hostinfo.Unlock()

	// Only overwrite existing record if we should win the handshake race
	overwrite := vpnIP > ip2int(f.certState.certificate.Details.Ips[0].IP)
	existing, err := f.handshakeManager.CheckAndComplete(hostinfo, 0, overwrite, f)
	if err != nil {
		switch err {
		case ErrAlreadySeen:
			msg = existing.HandshakePacket[2]
			f.messageMetrics.Tx(handshake, NebulaMessageSubType(msg[1]), 1)
			err := f.outside.WriteTo(msg, addr)
			if err != nil {
				l.WithField("vpnIp", IntIp(existing.hostId)).WithField("udpAddr", addr).
					WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("cached", true).
					WithError(err).Error("Failed to send handshake message")
			} else {
				l.WithField("vpnIp", IntIp(existing.hostId)).WithField("udpAddr", addr).
					WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("cached", true).
					Info("Handshake message sent")
			}
			return
		case ErrExistingHostInfo:
			// This means there was an existing tunnel and we didn't win
			// handshake avoidance
			l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				Info("Prevented a handshake race")

			// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
			f.SendMessageToVpnIp(test, testRequest, vpnIP, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			return
		case ErrLocalIndexCollision:
			// This means we failed to insert because of collision on localIndexId. Just let the next handshake packet retry
			l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				WithField("localIndex", hostinfo.localIndexId).WithField("collision", IntIp(existing.hostId)).
				Error("Failed to add HostInfo due to localIndex collision")
			return
		default:
			// Shouldn't happen, but just in case someone adds a new error type to CheckAndComplete
			// And we forget to update it here
			l.WithError(err).WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				Error("Failed to add HostInfo to HostMap")
			return
		}
	}

	// Do the send
	f.messageMetrics.Tx(handshake, NebulaMessageSubType(msg[1]), 1)
	err = f.outside.WriteTo(msg, addr)
	if err != nil {
		l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
			WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			WithError(err).Error("Failed to send handshake")
	} else {
		l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
			WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Info("Handshake message sent")
	}

	hostinfo.handshakeComplete()

	return
}

func ixHandshakeStage2(f *Interface, addr *udpAddr, hostinfo *HostInfo, packet []byte, h *Header) bool {
	if hostinfo == nil {
		return true
	}
	hostinfo.Lock()
	defer hostinfo.Unlock()

	if bytes.Equal(hostinfo.HandshakePacket[2], packet[HeaderLen:]) {
		l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("header", h).
			Info("Already seen this handshake packet")
		return false
	}

	ci := hostinfo.ConnectionState
	msg, eKey, dKey, err := ci.H.ReadMessage(nil, packet[HeaderLen:])
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("header", h).
			Error("Failed to call noise.ReadMessage")

		// We don't want to tear down the connection on a bad ReadMessage because it could be an attacker trying
		// to DOS us. Every other error condition after should to allow a possible good handshake to complete in the
		// near future
		return false
	} else if dKey == nil || eKey == nil {
		l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Error("Noise did not arrive at a key")
		return true
	}

	hs := &NebulaHandshake{}
	err = proto.Unmarshal(msg, hs)
	if err != nil || hs.Details == nil {
		l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).Error("Failed unmarshal handshake message")
		return true
	}

	remoteCert, err := RecombineCertAndValidate(ci.H, hs.Details.Cert)
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("cert", remoteCert).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Error("Invalid certificate from host")
		return true
	}

	vpnIP := ip2int(remoteCert.Details.Ips[0].IP)
	if vpnIP != hostinfo.hostId {
		l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("cert", remoteCert).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Error("Incorrect host responded to handshake")

		//TODO: remove this udpAddr from our cache
		// We don't want to tear down because maybe we can succeed with another ip address
		return false
	}

	hostinfo.HandshakePacket[2] = make([]byte, len(packet[HeaderLen:]))
	copy(hostinfo.HandshakePacket[2], packet[HeaderLen:])

	// Mark packet 2 as seen so it doesn't show up as missed
	ci.window.Update(2)

	certName := remoteCert.Details.Name
	fingerprint, _ := remoteCert.Sha256Sum()

	duration := time.Since(hostinfo.handshakeStart).Nanoseconds()
	l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
		WithField("certName", certName).
		WithField("fingerprint", fingerprint).
		WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
		WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
		WithField("durationNs", duration).
		Info("Handshake message received")

	//ci.remoteIndex = hs.ResponderIndex
	hostinfo.remoteIndexId = hs.Details.ResponderIndex
	hs.Details.Cert = ci.certState.rawCertificateNoKey

	/*
		hsBytes, err := proto.Marshal(hs)
		if err != nil {
			l.Debugln("Failed to marshal handshake: ", err)
			return
		}
	*/

	// Regardless of whether you are the sender or receiver, you should arrive here
	// and complete standing up the connection.

	ci.peerCert = remoteCert
	ci.dKey = NewNebulaCipherState(dKey)
	ci.eKey = NewNebulaCipherState(eKey)
	//l.Debugln("got symmetric pairs")

	hostinfo.SetRemote(addr)
	hostinfo.CreateRemoteCIDR(remoteCert)

	f.handshakeManager.Complete(hostinfo, f)
	hostinfo.handshakeComplete()
	f.metricHandshakes.Update(duration)

	return false
}
