package nebula

import (
	"sync/atomic"
	"time"

	"bytes"

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

	myIndex, err := generateIndex()
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to generate index")
		return
	}
	ci := hostinfo.ConnectionState
	f.handshakeManager.AddIndexHostInfo(myIndex, hostinfo)

	hsProto := &NebulaHandshakeDetails{
		InitiatorIndex: myIndex,
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
	atomic.AddUint64(ci.messageCounter, 1)

	msg, _, _, err := ci.H.WriteMessage(header, hsBytes)
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(vpnIp)).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to call noise.WriteMessage")
		return
	}

	hostinfo.HandshakePacket[0] = msg
	hostinfo.HandshakeReady = true
	hostinfo.handshakeStart = time.Now()

}

func ixHandshakeStage1(f *Interface, addr *udpAddr, hostinfo *HostInfo, packet []byte, h *Header) bool {
	var ip uint32
	if h.RemoteIndex == 0 {
		ci := f.newConnectionState(false, noise.HandshakeIX, f.PSK, 0)
		// Mark packet 1 as seen so it doesn't show up as missed

		msg, _, _, err := ci.H.ReadMessage(nil, packet[HeaderLen:])
		if err != nil {
			l.WithError(err).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to call noise.ReadMessage")
			//return true
			for _, key := range f.AltPSKs {
				ci = f.newConnectionState(false, noise.HandshakeIX, key, 0)
				// Mark packet 1 as seen so it doesn't show up as missed

				msg, _, _, err = ci.H.ReadMessage(nil, packet[HeaderLen:])
				if err == nil {
					continue
				}
			}
			return true
		}
		ci.window.Update(1)

		hs := &NebulaHandshake{}
		err = proto.Unmarshal(msg, hs)
		/*
			l.Debugln("GOT INDEX: ", hs.Details.InitiatorIndex)
		*/
		if err != nil || hs.Details == nil {
			l.WithError(err).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed unmarshal handshake message")
			return true
		}

		hostinfo, _ := f.handshakeManager.pendingHostMap.QueryReverseIndex(hs.Details.InitiatorIndex)
		if hostinfo != nil && bytes.Equal(hostinfo.HandshakePacket[0], packet[HeaderLen:]) {
			if msg, ok := hostinfo.HandshakePacket[2]; ok {
				err := f.outside.WriteTo(msg, addr)
				if err != nil {
					l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
						WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("cached", true).
						WithError(err).Error("Failed to send handshake message")
				} else {
					l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
						WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("cached", true).
						Info("Handshake message sent")
				}
				return false
			}

			l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).WithField("cached", true).
				WithField("packets", hostinfo.HandshakePacket).
				Error("Seen this handshake packet already but don't have a cached packet to return")
		}

		remoteCert, err := RecombineCertAndValidate(ci.H, hs.Details.Cert)
		if err != nil {
			l.WithError(err).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).WithField("cert", remoteCert).
				Info("Invalid certificate from host")
			return true
		}
		vpnIP := ip2int(remoteCert.Details.Ips[0].IP)

		myIndex, err := generateIndex()
		if err != nil {
			l.WithError(err).WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to generate index")
			return true
		}

		hostinfo, err = f.handshakeManager.AddIndex(myIndex, ci)
		if err != nil {
			l.WithError(err).WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Error adding index to connection manager")

			return true
		}
		l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
			WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
			WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
			Info("Handshake message received")

		hostinfo.remoteIndexId = hs.Details.InitiatorIndex
		hs.Details.ResponderIndex = myIndex
		hs.Details.Cert = ci.certState.rawCertificateNoKey

		hsBytes, err := proto.Marshal(hs)
		if err != nil {
			l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to marshal handshake message")
			return true
		}

		header := HeaderEncode(make([]byte, HeaderLen), Version, uint8(handshake), handshakeIXPSK0, hs.Details.InitiatorIndex, 2)
		msg, dKey, eKey, err := ci.H.WriteMessage(header, hsBytes)
		if err != nil {
			l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to call noise.WriteMessage")
			return true
		}

		if f.hostMap.CheckHandshakeCompleteIP(vpnIP) && vpnIP < ip2int(f.certState.certificate.Details.Ips[0].IP) {
			l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				Info("Prevented a handshake race")

			// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
			f.SendMessageToVpnIp(test, testRequest, vpnIP, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			return true
		}

		hostinfo.HandshakePacket[0] = make([]byte, len(packet[HeaderLen:]))
		copy(hostinfo.HandshakePacket[0], packet[HeaderLen:])

		// Regardless of whether you are the sender or receiver, you should arrive here
		// and complete standing up the connection.
		if dKey != nil && eKey != nil {
			hostinfo.HandshakePacket[2] = make([]byte, len(msg))
			copy(hostinfo.HandshakePacket[2], msg)

			err := f.outside.WriteTo(msg, addr)
			if err != nil {
				l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
					WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
					WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
					WithError(err).Error("Failed to send handshake")
			} else {
				l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
					WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
					WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
					Info("Handshake message sent")
			}

			ip = ip2int(remoteCert.Details.Ips[0].IP)
			ci.peerCert = remoteCert
			ci.dKey = NewNebulaCipherState(dKey)
			ci.eKey = NewNebulaCipherState(eKey)
			//l.Debugln("got symmetric pairs")

			//hostinfo.ClearRemotes()
			hostinfo.AddRemote(*addr)
			hostinfo.CreateRemoteCIDR(remoteCert)
			f.lightHouse.AddRemoteAndReset(ip, addr)
			if f.serveDns {
				dnsR.Add(remoteCert.Details.Name+".", remoteCert.Details.Ips[0].IP.String())
			}

			ho, err := f.hostMap.QueryVpnIP(vpnIP)
			if err == nil && ho.localIndexId != 0 {
				l.WithField("vpnIp", vpnIP).
					WithField("action", "removing stale index").
					WithField("index", ho.localIndexId).
					Debug("Handshake processing")
				f.hostMap.DeleteIndex(ho.localIndexId)
			}

			f.hostMap.AddIndexHostInfo(hostinfo.localIndexId, hostinfo)
			f.hostMap.AddVpnIPHostInfo(vpnIP, hostinfo)

			hostinfo.handshakeComplete()
		} else {
			l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				Error("Noise did not arrive at a key")
			return true
		}

	}

	f.hostMap.AddRemote(ip, addr)
	return false
}

func ixHandshakeStage2(f *Interface, addr *udpAddr, hostinfo *HostInfo, packet []byte, h *Header) bool {
	if hostinfo == nil {
		return true
	}

	if bytes.Equal(hostinfo.HandshakePacket[2], packet[HeaderLen:]) {
		l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("header", h).
			Error("Already seen this handshake packet")
		return false
	}

	ci := hostinfo.ConnectionState
	// Mark packet 2 as seen so it doesn't show up as missed
	ci.window.Update(2)

	hostinfo.HandshakePacket[2] = make([]byte, len(packet[HeaderLen:]))
	copy(hostinfo.HandshakePacket[2], packet[HeaderLen:])

	msg, eKey, dKey, err := ci.H.ReadMessage(nil, packet[HeaderLen:])
	if err != nil {
		l.WithError(err).WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("header", h).
			Error("Failed to call noise.ReadMessage")

		// We don't want to tear down the connection on a bad ReadMessage because it could be an attacker trying
		// to DOS us. Every other error condition after should to allow a possible good handshake to complete in the
		// near future
		return false
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

	duration := time.Since(hostinfo.handshakeStart).Nanoseconds()
	l.WithField("vpnIp", IntIp(vpnIP)).WithField("udpAddr", addr).
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
	if dKey != nil && eKey != nil {
		ip := ip2int(remoteCert.Details.Ips[0].IP)
		ci.peerCert = remoteCert
		ci.dKey = NewNebulaCipherState(dKey)
		ci.eKey = NewNebulaCipherState(eKey)
		//l.Debugln("got symmetric pairs")

		//hostinfo.ClearRemotes()
		f.hostMap.AddRemote(ip, addr)
		hostinfo.CreateRemoteCIDR(remoteCert)
		f.lightHouse.AddRemoteAndReset(ip, addr)
		if f.serveDns {
			dnsR.Add(remoteCert.Details.Name+".", remoteCert.Details.Ips[0].IP.String())
		}

		ho, err := f.hostMap.QueryVpnIP(vpnIP)
		if err == nil && ho.localIndexId != 0 {
			l.WithField("vpnIp", vpnIP).
				WithField("action", "removing stale index").
				WithField("index", ho.localIndexId).
				Debug("Handshake processing")
			f.hostMap.DeleteIndex(ho.localIndexId)
		}

		f.hostMap.AddVpnIPHostInfo(vpnIP, hostinfo)
		f.hostMap.AddIndexHostInfo(hostinfo.localIndexId, hostinfo)

		hostinfo.handshakeComplete()
		f.metricHandshakes.Update(duration)
	} else {
		l.WithField("vpnIp", IntIp(hostinfo.hostId)).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Error("Noise did not arrive at a key")
		return true
	}

	return false
}
