package nebula

import (
	"bytes"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/golang/protobuf/proto"
	"go.uber.org/zap"
)

// NOISE IX Handshakes

// This function constructs a handshake packet, but does not actually send it
// Sending is done by the handshake manager
func ixHandshakeStage0(f *Interface, vpnIp uint32, hostinfo *HostInfo) {
	// This queries the lighthouse if we don't know a remote for the host
	if hostinfo.remote == nil {
		ips, err := f.lightHouse.Query(vpnIp, f)
		if err != nil {
			l.Debug(err.Error())
		}
		for _, ip := range ips {
			hostinfo.AddRemote(ip)
		}
	}

	myIndex, err := generateIndex()
	if err != nil {
		l.Error(
			"failed to generate index",
			zap.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
		)
		return
	}
	ci := hostinfo.ConnectionState
	f.handshakeManager.AddIndexHostInfo(myIndex, hostinfo)

	hsProto := &NebulaHandshakeDetails{
		InitiatorIndex: myIndex,
		Time:           uint64(time.Now().Unix()),
		Cert:           ci.certState.rawCertificateNoKey,
	}

	hs := &NebulaHandshake{
		Details: hsProto,
	}
	hsBytes, err := proto.Marshal(hs)

	if err != nil {
		l.Error(
			"failed to marshal handshake message",
			zap.Uint32("vpnIp", uint32(IntIp(vpnIp))),
			zap.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
		)
		return
	}

	header := HeaderEncode(make([]byte, HeaderLen), Version, uint8(handshake), handshakeIXPSK0, 0, 1)
	atomic.AddUint64(ci.messageCounter, 1)

	msg, _, _, err := ci.H.WriteMessage(header, hsBytes)
	if err != nil {
		l.Error(
			"failed to call noise.WriteMessage",
			zap.Uint32("vpnIp", uint32(IntIp(vpnIp))),
			zap.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
		)
		return
	}
	hostinfo.Lock()
	hostinfo.HandshakePacket[0] = msg
	hostinfo.HandshakeReady = true
	hostinfo.handshakeStart = time.Now()
	hostinfo.Unlock()

}

func ixHandshakeStage1(f *Interface, addr *udpAddr, hostinfo *HostInfo, packet []byte, h *Header) bool {
	var ip uint32
	if h.RemoteIndex == 0 {
		ci := f.newConnectionState(false, noise.HandshakeIX, []byte{}, 0)
		// Mark packet 1 as seen so it doesn't show up as missed
		ci.window.Update(1)

		msg, _, _, err := ci.H.ReadMessage(nil, packet[HeaderLen:])
		if err != nil {
			l.Error(
				"failed to call noise.WriteMessage",
				zap.Uint32("udpIP", addr.IP),
				zap.Uint16("udpPort", addr.Port),
				zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)
			return true
		}

		hs := &NebulaHandshake{}
		err = proto.Unmarshal(msg, hs)
		/*
			l.Debugln("GOT INDEX: ", hs.Details.InitiatorIndex)
		*/
		if err != nil || hs.Details == nil {
			l.Error(
				"failed to unmarshal handshake message",
				zap.Uint32("udpIP", addr.IP),
				zap.Uint16("udpPort", addr.Port),
				zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)
			return true
		}

		hostinfo, _ := f.handshakeManager.pendingHostMap.QueryReverseIndex(hs.Details.InitiatorIndex)
		if hostinfo != nil {
			hostinfo.Lock()
			if bytes.Equal(hostinfo.HandshakePacket[0], packet[HeaderLen:]) {
				if msg, ok := hostinfo.HandshakePacket[2]; ok {
					f.messageMetrics.Tx(handshake, NebulaMessageSubType(msg[1]), 1)
					err := f.outside.WriteTo(msg, addr)
					if err != nil {
						l.Error(
							"failed to send handshake message",
							zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
							zap.Uint32("udpIP", addr.IP),
							zap.Uint16("udpPort", addr.Port),
							zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
							zap.Bool("cached", true),
						)
					} else {
						l.Error(
							"handshake message sent",
							zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
							zap.Uint32("udpIP", addr.IP),
							zap.Uint16("udpPort", addr.Port),
							zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
							zap.Bool("cached", true),
						)
					}
					hostinfo.Unlock()
					return false
				}
				l.Error(
					"seen this handshake packet already but don't have a cached packet to return",
					zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
					zap.Uint32("udpIP", addr.IP),
					zap.Uint16("udpPort", addr.Port),
					zap.Any("packets", hostinfo.HandshakePacket),
					zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
					zap.Bool("cached", true),
				)
			}
			hostinfo.Unlock()
		}

		remoteCert, err := RecombineCertAndValidate(ci.H, hs.Details.Cert)
		if err != nil {
			l.Info(
				"invalid certificate from host",
				zap.Uint32("udpIP", addr.IP),
				zap.Uint16("udpPort", addr.Port),
				zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
				zap.Any("cert", remoteCert),
			)
			return true
		}
		vpnIP := ip2int(remoteCert.Details.Ips[0].IP)
		certName := remoteCert.Details.Name
		fingerprint, _ := remoteCert.Sha256Sum()

		myIndex, err := generateIndex()
		if err != nil {
			l.Error(
				"failed to generate index",
				zap.Uint32("udpIP", addr.IP),
				zap.Uint16("udpPort", addr.Port),
				zap.Uint32("vpnIp", uint32(IntIp(vpnIP))),
				zap.String("certName", certName),
				zap.String("fingerprint", fingerprint),
				zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)
			return true
		}

		hostinfo, err = f.handshakeManager.AddIndex(myIndex, ci)
		if err != nil {
			l.Error(
				"failed adding index to connection manager",
				zap.Uint32("udpIP", addr.IP),
				zap.Uint16("udpPort", addr.Port),
				zap.Uint32("vpnIp", uint32(IntIp(vpnIP))),
				zap.String("certName", certName),
				zap.String("fingerprint", fingerprint),
				zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)
			return true
		}

		l.Info(
			"handshake message received",
			zap.Uint32("udpIP", addr.IP),
			zap.Uint16("udpPort", addr.Port),
			zap.Uint32("vpnIp", uint32(IntIp(vpnIP))),
			zap.String("certName", certName),
			zap.String("fingerprint", fingerprint),
			zap.Uint32("initiatorIndex", hs.Details.InitiatorIndex),
			zap.Uint32("responderIndex", hs.Details.ResponderIndex),
			zap.Uint32("remoteIndex", h.RemoteIndex),
			zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)

		hostinfo.remoteIndexId = hs.Details.InitiatorIndex
		hs.Details.ResponderIndex = myIndex
		hs.Details.Cert = ci.certState.rawCertificateNoKey

		hsBytes, err := proto.Marshal(hs)
		if err != nil {
			l.Error(
				"failed to marshal handshake message",
				zap.Uint32("udpIP", addr.IP),
				zap.Uint16("udpPort", addr.Port),
				zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
				zap.String("certName", certName),
				zap.String("fingerprint", fingerprint),
				zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)
			return true
		}

		header := HeaderEncode(make([]byte, HeaderLen), Version, uint8(handshake), handshakeIXPSK0, hs.Details.InitiatorIndex, 2)
		msg, dKey, eKey, err := ci.H.WriteMessage(header, hsBytes)
		if err != nil {
			l.Error(
				"failed to call noise.WriteMessage",
				zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
				zap.String("certName", certName),
				zap.String("fingerprint", fingerprint),
				zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)
			return true
		}

		if f.hostMap.CheckHandshakeCompleteIP(vpnIP) && vpnIP < ip2int(f.certState.certificate.Details.Ips[0].IP) {
			l.Info(
				"prevented a handshake race",
				zap.Uint32("udpIP", addr.IP),
				zap.Uint16("udpPort", addr.Port),
				zap.Uint32("vpnIp", uint32(IntIp(vpnIP))),
				zap.String("certName", certName),
				zap.String("fingerprint", fingerprint),
				zap.Uint32("initiatorIndex", hs.Details.InitiatorIndex),
				zap.Uint32("responderIndex", hs.Details.ResponderIndex),
				zap.Uint32("remoteIndex", h.RemoteIndex),
				zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)

			// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
			f.SendMessageToVpnIp(test, testRequest, vpnIP, []byte(""), make([]byte, 12), make([]byte, mtu))
			return true
		}

		hostinfo.HandshakePacket[0] = make([]byte, len(packet[HeaderLen:]))
		copy(hostinfo.HandshakePacket[0], packet[HeaderLen:])

		// Regardless of whether you are the sender or receiver, you should arrive here
		// and complete standing up the connection.
		if dKey != nil && eKey != nil {
			hostinfo.HandshakePacket[2] = make([]byte, len(msg))
			copy(hostinfo.HandshakePacket[2], msg)

			f.messageMetrics.Tx(handshake, NebulaMessageSubType(msg[1]), 1)
			err := f.outside.WriteTo(msg, addr)
			if err != nil {
				l.Error(
					"failed to send handshake message",
					zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
					zap.Uint32("udpIP", addr.IP),
					zap.Uint16("udpPort", addr.Port),
					zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
					zap.Uint32("initiatorIndex", hs.Details.InitiatorIndex),
					zap.Uint32("responderIndex", hs.Details.ResponderIndex),
					zap.Uint32("remoteIndex", h.RemoteIndex),
				)
			} else {
				l.Info(
					"handshake message sent",
					zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
					zap.Uint32("udpIP", addr.IP),
					zap.Uint16("udpPort", addr.Port),
					zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
					zap.Uint32("initiatorIndex", hs.Details.InitiatorIndex),
					zap.Uint32("responderIndex", hs.Details.ResponderIndex),
					zap.Uint32("remoteIndex", h.RemoteIndex),
				)
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

				l.Debug(
					"handshake processing",
					zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
					zap.Uint32("udpIP", addr.IP),
					zap.Uint16("udpPort", addr.Port),
					zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
					zap.String("fingerprint", fingerprint),
					zap.String("certName", certName),
					zap.Uint32("index", ho.localIndexId),
					zap.String("action", "removing stale index"),
				)
				f.hostMap.DeleteIndex(ho.localIndexId)
			}

			f.hostMap.AddIndexHostInfo(hostinfo.localIndexId, hostinfo)
			f.hostMap.AddVpnIPHostInfo(vpnIP, hostinfo)

			hostinfo.handshakeComplete()
		} else {
			l.Error(
				"noise did not arrive at key",
				zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
				zap.Uint32("udpIP", addr.IP),
				zap.Uint16("udpPort", addr.Port),
				zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
				zap.String("fingerprint", fingerprint),
				zap.String("certName", certName),
			)
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
	hostinfo.RLock()
	if bytes.Equal(hostinfo.HandshakePacket[2], packet[HeaderLen:]) {
		hostinfo.RUnlock()
		l.Error(
			"already seen this handshake packet",
			zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
			zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
			zap.Uint32("udpIP", addr.IP),
			zap.Uint16("udpPort", addr.Port),
			zap.Any("header", h),
		)
		return false
	}
	hostinfo.RUnlock()
	ci := hostinfo.ConnectionState
	// Mark packet 2 as seen so it doesn't show up as missed
	ci.window.Update(2)
	hostinfo.Lock()
	hostinfo.HandshakePacket[2] = make([]byte, len(packet[HeaderLen:]))
	copy(hostinfo.HandshakePacket[2], packet[HeaderLen:])
	hostinfo.Unlock()
	msg, eKey, dKey, err := ci.H.ReadMessage(nil, packet[HeaderLen:])
	if err != nil {

		l.Error(
			"failed to call noise.ReadMessage",
			zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
			zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
			zap.Uint32("udpIP", addr.IP),
			zap.Uint16("udpPort", addr.Port),
			zap.Any("header", h),
		)

		// We don't want to tear down the connection on a bad ReadMessage because it could be an attacker trying
		// to DOS us. Every other error condition after should to allow a possible good handshake to complete in the
		// near future
		return false
	}

	hs := &NebulaHandshake{}
	err = proto.Unmarshal(msg, hs)
	if err != nil || hs.Details == nil {

		l.Error(
			"failed unmarshal handshake message",
			zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
			zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
			zap.Uint32("udpIP", addr.IP),
			zap.Uint16("udpPort", addr.Port),
			zap.Any("header", h),
		)
		return true
	}

	remoteCert, err := RecombineCertAndValidate(ci.H, hs.Details.Cert)
	if err != nil {
		l.Error(
			"invalid certificate from host",
			zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
			zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
			zap.Uint32("udpIP", addr.IP),
			zap.Uint16("udpPort", addr.Port),
			zap.Any("cert", remoteCert),
		)
		return true
	}
	vpnIP := ip2int(remoteCert.Details.Ips[0].IP)
	certName := remoteCert.Details.Name
	fingerprint, _ := remoteCert.Sha256Sum()

	duration := time.Since(hostinfo.handshakeStart).Nanoseconds()

	l.Info(
		"handshake message received",
		zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
		zap.Uint32("udpIP", addr.IP),
		zap.Uint16("udpPort", addr.Port),
		zap.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
		zap.Uint32("initiatorIndex", hs.Details.InitiatorIndex),
		zap.Uint32("responderIndex", hs.Details.ResponderIndex),
		zap.Uint32("remoteIndex", h.RemoteIndex),
		zap.Int64("durationNs", duration),
		zap.String("fingerprint", fingerprint),
		zap.String("certName", certName),
	)

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
		ci.mx.Lock()
		ci.peerCert = remoteCert
		ci.dKey = NewNebulaCipherState(dKey)
		ci.eKey = NewNebulaCipherState(eKey)
		ci.mx.Unlock()
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
			l.Debug(
				"handshake processing",
				zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
				zap.Uint32("udpIP", addr.IP),
				zap.Uint16("udpPort", addr.Port),
				zap.String("fingerprint", fingerprint),
				zap.String("certName", certName),
				zap.Uint32("index", ho.localIndexId),
				zap.String("action", "removing stale index"),
			)
			f.hostMap.DeleteIndex(ho.localIndexId)
		}

		f.hostMap.AddVpnIPHostInfo(vpnIP, hostinfo)
		f.hostMap.AddIndexHostInfo(hostinfo.localIndexId, hostinfo)

		hostinfo.handshakeComplete()
		f.metricHandshakes.Update(duration)
	} else {
		l.Error(
			"noise did not arrive at key",
			zap.Uint32("vpnIp", uint32(IntIp(hostinfo.hostId))),
			zap.Uint32("udpIP", addr.IP),
			zap.Uint16("udpPort", addr.Port),
			zap.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			zap.String("fingerprint", fingerprint),
			zap.String("certName", certName),
		)
		return true
	}

	return false
}
