package nebula

import (
	"net/netip"
	"slices"
	"time"

	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

// NOISE IX Handshakes

// This function constructs a handshake packet, but does not actually send it
// Sending is done by the handshake manager
func ixHandshakeStage0(f *Interface, hh *HandshakeHostInfo) bool {
	err := f.handshakeManager.allocateIndex(hh)
	if err != nil {
		f.l.WithError(err).WithField("vpnAddrs", hh.hostinfo.vpnAddrs).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to generate index")
		return false
	}

	//if we're connecting to a v6 address, always use v2 certs
	cs := f.pki.getCertState()
	v := cs.defaultVersion
	if cs.v2Cert != nil {
		for _, a := range hh.hostinfo.vpnAddrs {
			if a.Is6() {
				v = cert.Version2
				break
			}
		}
	}

	ci := NewConnectionState(f.l, cs, v, true, noise.HandshakeIX)
	hh.hostinfo.ConnectionState = ci

	hs := &NebulaHandshake{
		Details: &NebulaHandshakeDetails{
			InitiatorIndex: hh.hostinfo.localIndexId,
			Time:           uint64(time.Now().UnixNano()),
			Cert:           cs.getHandshakeBytes(v),
			CertVersion:    uint32(v),
		},
	}

	hsBytes, err := hs.Marshal()
	if err != nil {
		f.l.WithError(err).WithField("vpnAddrs", hh.hostinfo.vpnAddrs).WithField("version", v).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to marshal handshake message")
		return false
	}

	h := header.Encode(make([]byte, header.Len), header.Version, header.Handshake, header.HandshakeIXPSK0, 0, 1)

	msg, _, _, err := ci.H.WriteMessage(h, hsBytes)
	if err != nil {
		f.l.WithError(err).WithField("vpnAddrs", hh.hostinfo.vpnAddrs).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to call noise.WriteMessage")
		return false
	}

	// We are sending handshake packet 1, so we don't expect to receive
	// handshake packet 1 from the responder
	ci.window.Update(f.l, 1)

	hh.hostinfo.HandshakePacket[0] = msg
	hh.ready = true
	return true
}

func ixHandshakeStage1(f *Interface, addr netip.AddrPort, via *ViaSender, packet []byte, h *header.H) {
	cs := f.pki.getCertState()
	ci := NewConnectionState(f.l, cs, cs.defaultVersion, false, noise.HandshakeIX)
	// Mark packet 1 as seen so it doesn't show up as missed
	ci.window.Update(f.l, 1)

	msg, _, _, err := ci.H.ReadMessage(nil, packet[header.Len:])
	if err != nil {
		f.l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to call noise.ReadMessage")
		return
	}

	hs := &NebulaHandshake{}
	err = hs.Unmarshal(msg)
	if err != nil || hs.Details == nil {
		f.l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed unmarshal handshake message")
		return
	}

	remoteCert, err := cert.RecombineAndValidate(cert.Version(hs.Details.CertVersion), hs.Details.Cert, ci.H.PeerStatic(), ci.Curve(), f.pki.GetCAPool())
	if err != nil {
		e := f.l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"})

		if f.l.Level > logrus.DebugLevel {
			e = e.WithField("cert", remoteCert)
		}

		e.Info("Invalid certificate from host")
		return
	}

	if remoteCert.Certificate.Version() != ci.myCert.Version() {
		// We started off using the wrong certificate version, lets see if we can match the version that was sent to us
		rc := cs.getCertificate(remoteCert.Certificate.Version())
		//TODO: anywhere we are logging remoteCert needs to be remoteCert.Certificate OR we make a pass through func on CachedCertificate
		if rc == nil {
			f.l.WithError(err).WithField("udpAddr", addr).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).WithField("cert", remoteCert).
				Info("Unable to handshake with host due to missing certificate version")
			return
		}

		// Record the certificate we are actually using
		ci.myCert = rc
	}

	if len(remoteCert.Certificate.Networks()) == 0 {
		e := f.l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"})

		if f.l.Level > logrus.DebugLevel {
			e = e.WithField("cert", remoteCert)
		}

		e.Info("Invalid vpn ip from host")
		return
	}

	var vpnAddrs []netip.Addr
	certName := remoteCert.Certificate.Name()
	fingerprint := remoteCert.Fingerprint
	issuer := remoteCert.Certificate.Issuer()

	for _, network := range remoteCert.Certificate.Networks() {
		vpnAddr := network.Addr()
		_, found := f.myVpnAddrsTable.Lookup(vpnAddr)
		if found {
			f.l.WithField("vpnAddr", vpnAddr).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Refusing to handshake with myself")
			return
		}

		if addr.IsValid() {
			if !f.lightHouse.GetRemoteAllowList().Allow(vpnAddr, addr.Addr()) {
				f.l.WithField("vpnAddr", vpnAddr).WithField("udpAddr", addr).Debug("lighthouse.remote_allow_list denied incoming handshake")
				return
			}
		}

		vpnAddrs = append(vpnAddrs, vpnAddr)
	}

	myIndex, err := generateIndex(f.l)
	if err != nil {
		f.l.WithError(err).WithField("vpnAddrs", vpnAddrs).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("issuer", issuer).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to generate index")
		return
	}

	hostinfo := &HostInfo{
		ConnectionState:   ci,
		localIndexId:      myIndex,
		remoteIndexId:     hs.Details.InitiatorIndex,
		vpnAddrs:          vpnAddrs,
		HandshakePacket:   make(map[uint8][]byte, 0),
		lastHandshakeTime: hs.Details.Time,
		relayState: RelayState{
			relays:         map[netip.Addr]struct{}{},
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}

	f.l.WithField("vpnAddrs", vpnAddrs).WithField("udpAddr", addr).
		WithField("certName", certName).
		WithField("fingerprint", fingerprint).
		WithField("issuer", issuer).
		WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
		WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
		Info("Handshake message received")

	hs.Details.ResponderIndex = myIndex
	hs.Details.Cert = cs.getHandshakeBytes(ci.myCert.Version())
	hs.Details.CertVersion = uint32(ci.myCert.Version())
	// Update the time in case their clock is way off from ours
	hs.Details.Time = uint64(time.Now().UnixNano())

	hsBytes, err := hs.Marshal()
	if err != nil {
		f.l.WithError(err).WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("issuer", issuer).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to marshal handshake message")
		return
	}

	nh := header.Encode(make([]byte, header.Len), header.Version, header.Handshake, header.HandshakeIXPSK0, hs.Details.InitiatorIndex, 2)
	msg, dKey, eKey, err := ci.H.WriteMessage(nh, hsBytes)
	if err != nil {
		f.l.WithError(err).WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("issuer", issuer).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to call noise.WriteMessage")
		return
	} else if dKey == nil || eKey == nil {
		f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("issuer", issuer).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Noise did not arrive at a key")
		return
	}

	hostinfo.HandshakePacket[0] = make([]byte, len(packet[header.Len:]))
	copy(hostinfo.HandshakePacket[0], packet[header.Len:])

	// Regardless of whether you are the sender or receiver, you should arrive here
	// and complete standing up the connection.
	hostinfo.HandshakePacket[2] = make([]byte, len(msg))
	copy(hostinfo.HandshakePacket[2], msg)

	// We are sending handshake packet 2, so we don't expect to receive
	// handshake packet 2 from the initiator.
	ci.window.Update(f.l, 2)

	ci.peerCert = remoteCert
	ci.dKey = NewNebulaCipherState(dKey)
	ci.eKey = NewNebulaCipherState(eKey)

	hostinfo.remotes = f.lightHouse.QueryCache(vpnAddrs)
	hostinfo.SetRemote(addr)
	hostinfo.CreateRemoteCIDR(remoteCert.Certificate)

	existing, err := f.handshakeManager.CheckAndComplete(hostinfo, 0, f)
	if err != nil {
		switch err {
		case ErrAlreadySeen:
			// Update remote if preferred
			if existing.SetRemoteIfPreferred(f.hostMap, addr) {
				// Send a test packet to ensure the other side has also switched to
				// the preferred remote
				f.SendMessageToVpnIp(header.Test, header.TestRequest, vpnAddrs[0], []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			}

			msg = existing.HandshakePacket[2]
			f.messageMetrics.Tx(header.Handshake, header.MessageSubType(msg[1]), 1)
			if addr.IsValid() {
				err := f.outside.WriteTo(msg, addr)
				if err != nil {
					f.l.WithField("vpnAddrs", existing.vpnAddrs).WithField("udpAddr", addr).
						WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("cached", true).
						WithError(err).Error("Failed to send handshake message")
				} else {
					f.l.WithField("vpnAddrs", existing.vpnAddrs).WithField("udpAddr", addr).
						WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("cached", true).
						Info("Handshake message sent")
				}
				return
			} else {
				if via == nil {
					f.l.Error("Handshake send failed: both addr and via are nil.")
					return
				}
				hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
				f.SendVia(via.relayHI, via.relay, msg, make([]byte, 12), make([]byte, mtu), false)
				f.l.WithField("vpnAddrs", existing.vpnAddrs).WithField("relay", via.relayHI.vpnAddrs[0]).
					WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("cached", true).
					Info("Handshake message sent")
				return
			}
		case ErrExistingHostInfo:
			// This means there was an existing tunnel and this handshake was older than the one we are currently based on
			f.l.WithField("vpnAddrs", vpnAddrs).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("oldHandshakeTime", existing.lastHandshakeTime).
				WithField("newHandshakeTime", hostinfo.lastHandshakeTime).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				Info("Handshake too old")

			// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
			f.SendMessageToVpnIp(header.Test, header.TestRequest, vpnAddrs[0], []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			return
		case ErrLocalIndexCollision:
			// This means we failed to insert because of collision on localIndexId. Just let the next handshake packet retry
			f.l.WithField("vpnAddrs", vpnAddrs).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				WithField("localIndex", hostinfo.localIndexId).WithField("collision", existing.vpnAddrs).
				Error("Failed to add HostInfo due to localIndex collision")
			return
		default:
			// Shouldn't happen, but just in case someone adds a new error type to CheckAndComplete
			// And we forget to update it here
			f.l.WithError(err).WithField("vpnAddrs", vpnAddrs).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				Error("Failed to add HostInfo to HostMap")
			return
		}
	}

	// Do the send
	f.messageMetrics.Tx(header.Handshake, header.MessageSubType(msg[1]), 1)
	if addr.IsValid() {
		err = f.outside.WriteTo(msg, addr)
		if err != nil {
			f.l.WithField("vpnAddrs", vpnAddrs).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
				WithError(err).Error("Failed to send handshake")
		} else {
			f.l.WithField("vpnAddrs", vpnAddrs).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
				Info("Handshake message sent")
		}
	} else {
		if via == nil {
			f.l.Error("Handshake send failed: both addr and via are nil.")
			return
		}
		hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
		f.SendVia(via.relayHI, via.relay, msg, make([]byte, 12), make([]byte, mtu), false)
		f.l.WithField("vpnAddrs", vpnAddrs).WithField("relay", via.relayHI.vpnAddrs[0]).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("issuer", issuer).
			WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
			WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Info("Handshake message sent")
	}

	f.connectionManager.AddTrafficWatch(hostinfo.localIndexId)

	hostinfo.remotes.ResetBlockedRemotes()

	return
}

func ixHandshakeStage2(f *Interface, addr netip.AddrPort, via *ViaSender, hh *HandshakeHostInfo, packet []byte, h *header.H) bool {
	if hh == nil {
		// Nothing here to tear down, got a bogus stage 2 packet
		return true
	}

	hh.Lock()
	defer hh.Unlock()

	hostinfo := hh.hostinfo
	if addr.IsValid() {
		//TODO: this is kind of nonsense now
		if !f.lightHouse.GetRemoteAllowList().Allow(hostinfo.vpnAddrs[0], addr.Addr()) {
			f.l.WithField("vpnIp", hostinfo.vpnAddrs).WithField("udpAddr", addr).Debug("lighthouse.remote_allow_list denied incoming handshake")
			return false
		}
	}

	ci := hostinfo.ConnectionState
	msg, eKey, dKey, err := ci.H.ReadMessage(nil, packet[header.Len:])
	if err != nil {
		f.l.WithError(err).WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("header", h).
			Error("Failed to call noise.ReadMessage")

		// We don't want to tear down the connection on a bad ReadMessage because it could be an attacker trying
		// to DOS us. Every other error condition after should to allow a possible good handshake to complete in the
		// near future
		return false
	} else if dKey == nil || eKey == nil {
		f.l.WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Error("Noise did not arrive at a key")

		// This should be impossible in IX but just in case, if we get here then there is no chance to recover
		// the handshake state machine. Tear it down
		return true
	}

	hs := &NebulaHandshake{}
	err = hs.Unmarshal(msg)
	if err != nil || hs.Details == nil {
		f.l.WithError(err).WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).Error("Failed unmarshal handshake message")

		// The handshake state machine is complete, if things break now there is no chance to recover. Tear down and start again
		return true
	}

	remoteCert, err := cert.RecombineAndValidate(cert.Version(hs.Details.CertVersion), hs.Details.Cert, ci.H.PeerStatic(), ci.Curve(), f.pki.GetCAPool())
	if err != nil {
		e := f.l.WithError(err).WithField("vpnAddrs", hostinfo.vpnAddrs).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"})

		if f.l.Level > logrus.DebugLevel {
			e = e.WithField("cert", remoteCert)
		}

		e.Error("Invalid certificate from host")

		// The handshake state machine is complete, if things break now there is no chance to recover. Tear down and start again
		return true
	}

	if len(remoteCert.Certificate.Networks()) == 0 {
		e := f.l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"})

		if f.l.Level > logrus.DebugLevel {
			e = e.WithField("cert", remoteCert)
		}

		e.Info("Invalid vpn ip from host")
		return true
	}

	vpnNetworks := remoteCert.Certificate.Networks()
	certName := remoteCert.Certificate.Name()
	fingerprint := remoteCert.Fingerprint
	issuer := remoteCert.Certificate.Issuer()

	vpnAddrs := make([]netip.Addr, len(vpnNetworks))
	for i, n := range vpnNetworks {
		vpnAddrs[i] = n.Addr()
	}

	// Ensure the right host responded
	if !slices.Contains(vpnAddrs, hostinfo.vpnAddrs[0]) {
		f.l.WithField("intendedVpnAddrs", hostinfo.vpnAddrs).WithField("haveVpnNetworks", vpnNetworks).
			WithField("udpAddr", addr).WithField("certName", certName).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Info("Incorrect host responded to handshake")

		// Release our old handshake from pending, it should not continue
		f.handshakeManager.DeleteHostInfo(hostinfo)

		// Create a new hostinfo/handshake for the intended vpn ip
		f.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], func(newHH *HandshakeHostInfo) {
			//TODO: this doesnt know if its being added or is being used for caching a packet
			// Block the current used address
			newHH.hostinfo.remotes = hostinfo.remotes
			newHH.hostinfo.remotes.BlockRemote(addr)

			// Get the correct remote list for the host we did handshake with
			hostinfo.remotes = f.lightHouse.QueryCache(vpnAddrs)

			f.l.WithField("blockedUdpAddrs", newHH.hostinfo.remotes.CopyBlockedRemotes()).WithField("vpnNetworks", vpnNetworks).
				WithField("remotes", newHH.hostinfo.remotes.CopyAddrs(f.hostMap.GetPreferredRanges())).
				Info("Blocked addresses for handshakes")

			// Swap the packet store to benefit the original intended recipient
			newHH.packetStore = hh.packetStore
			hh.packetStore = []*cachedPacket{}

			// Finally, put the correct vpn addrs in the host info, tell them to close the tunnel, and return true to tear down
			hostinfo.vpnAddrs = vpnAddrs
			f.sendCloseTunnel(hostinfo)
		})

		return true
	}

	// Mark packet 2 as seen so it doesn't show up as missed
	ci.window.Update(f.l, 2)

	duration := time.Since(hh.startTime).Nanoseconds()
	f.l.WithField("vpnNetworks", vpnNetworks).WithField("udpAddr", addr).
		WithField("certName", certName).
		WithField("fingerprint", fingerprint).
		WithField("issuer", issuer).
		WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
		WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
		WithField("durationNs", duration).
		WithField("sentCachedPackets", len(hh.packetStore)).
		Info("Handshake message received")

	hostinfo.remoteIndexId = hs.Details.ResponderIndex
	hostinfo.lastHandshakeTime = hs.Details.Time
	hostinfo.vpnAddrs = vpnAddrs

	// Store their cert and our symmetric keys
	ci.peerCert = remoteCert
	ci.dKey = NewNebulaCipherState(dKey)
	ci.eKey = NewNebulaCipherState(eKey)

	// Make sure the current udpAddr being used is set for responding
	if addr.IsValid() {
		hostinfo.SetRemote(addr)
	} else {
		hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
	}

	// Build up the radix for the firewall if we have subnets in the cert
	hostinfo.CreateRemoteCIDR(remoteCert.Certificate)

	// Complete our handshake and update metrics, this will replace any existing tunnels for this vpnIp
	f.handshakeManager.Complete(hostinfo, f)
	f.connectionManager.AddTrafficWatch(hostinfo.localIndexId)

	if f.l.Level >= logrus.DebugLevel {
		hostinfo.logger(f.l).Debugf("Sending %d stored packets", len(hh.packetStore))
	}

	if len(hh.packetStore) > 0 {
		nb := make([]byte, 12, 12)
		out := make([]byte, mtu)
		for _, cp := range hh.packetStore {
			cp.callback(cp.messageType, cp.messageSubType, hostinfo, cp.packet, nb, out)
		}
		f.cachedPacketMetrics.sent.Inc(int64(len(hh.packetStore)))
	}

	hostinfo.remotes.ResetBlockedRemotes()
	f.metricHandshakes.Update(duration)

	return false
}
