package nebula

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
)

// NOISE IX Handshakes

// This function constructs a handshake packet, but does not actually send it
// Sending is done by the handshake manager
func ixHandshakeStage0(f *Interface, hh *HandshakeHostInfo) bool {
	err := f.handshakeManager.allocateIndex(hh)
	if err != nil {
		f.l.Error("Failed to generate index",
			slog.Any("error", err),
			slog.Any("vpnAddrs", hh.hostinfo.vpnAddrs),
			slog.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
		)
		return false
	}

	cs := f.pki.getCertState()
	v := cs.initiatingVersion
	if hh.initiatingVersionOverride != cert.VersionPre1 {
		v = hh.initiatingVersionOverride
	} else if v < cert.Version2 {
		// If we're connecting to a v6 address we should encourage use of a V2 cert
		for _, a := range hh.hostinfo.vpnAddrs {
			if a.Is6() {
				v = cert.Version2
				break
			}
		}
	}

	crt := cs.getCertificate(v)
	if crt == nil {
		f.l.Error("Unable to handshake with host because no certificate is available",
			slog.Any("vpnAddrs", hh.hostinfo.vpnAddrs),
			slog.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
			slog.Any("certVersion", v),
		)
		return false
	}

	crtHs := cs.getHandshakeBytes(v)
	if crtHs == nil {
		f.l.Error("Unable to handshake with host because no certificate handshake bytes is available",
			slog.Any("vpnAddrs", hh.hostinfo.vpnAddrs),
			slog.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
			slog.Any("certVersion", v),
		)
		return false
	}

	ci, err := NewConnectionState(cs, crt, true, noise.HandshakeIX)
	if err != nil {
		f.l.Error("Failed to create connection state",
			slog.Any("error", err),
			slog.Any("vpnAddrs", hh.hostinfo.vpnAddrs),
			slog.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
			slog.Any("certVersion", v),
		)
		return false
	}
	hh.hostinfo.ConnectionState = ci

	hs := &NebulaHandshake{
		Details: &NebulaHandshakeDetails{
			InitiatorIndex: hh.hostinfo.localIndexId,
			Time:           uint64(time.Now().UnixNano()),
			Cert:           crtHs,
			CertVersion:    uint32(v),
		},
	}

	hsBytes, err := hs.Marshal()
	if err != nil {
		f.l.Error("Failed to marshal handshake message",
			slog.Any("error", err),
			slog.Any("vpnAddrs", hh.hostinfo.vpnAddrs),
			slog.Any("certVersion", v),
			slog.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
		)
		return false
	}

	h := header.Encode(make([]byte, header.Len), header.Version, header.Handshake, header.HandshakeIXPSK0, 0, 1)

	msg, _, _, err := ci.H.WriteMessage(h, hsBytes)
	if err != nil {
		f.l.Error("Failed to call noise.WriteMessage",
			slog.Any("error", err),
			slog.Any("vpnAddrs", hh.hostinfo.vpnAddrs),
			slog.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
		)
		return false
	}

	// We are sending handshake packet 1, so we don't expect to receive
	// handshake packet 1 from the responder
	ci.window.Update(f.l, 1)

	hh.hostinfo.HandshakePacket[0] = msg
	hh.ready = true
	return true
}

func ixHandshakeStage1(f *Interface, via ViaSender, packet []byte, h *header.H) {
	cs := f.pki.getCertState()
	crt := cs.GetDefaultCertificate()
	if crt == nil {
		f.l.Error("Unable to handshake with host because no certificate is available",
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 0, "style": "ix_psk0"}),
			slog.Any("certVersion", cs.initiatingVersion),
		)
		return
	}

	ci, err := NewConnectionState(cs, crt, false, noise.HandshakeIX)
	if err != nil {
		f.l.Error("Failed to create connection state",
			slog.Any("error", err),
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)
		return
	}

	// Mark packet 1 as seen so it doesn't show up as missed
	ci.window.Update(f.l, 1)

	msg, _, _, err := ci.H.ReadMessage(nil, packet[header.Len:])
	if err != nil {
		f.l.Error("Failed to call noise.ReadMessage",
			slog.Any("error", err),
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)
		return
	}

	hs := &NebulaHandshake{}
	err = hs.Unmarshal(msg)
	if err != nil || hs.Details == nil {
		f.l.Error("Failed unmarshal handshake message",
			slog.Any("error", err),
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)
		return
	}

	rc, err := cert.Recombine(cert.Version(hs.Details.CertVersion), hs.Details.Cert, ci.H.PeerStatic(), ci.Curve())
	if err != nil {
		f.l.Info("Handshake did not contain a certificate",
			slog.Any("error", err),
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)
		return
	}

	remoteCert, err := f.pki.GetCAPool().VerifyCertificate(time.Now(), rc)
	if err != nil {
		fp, fperr := rc.Fingerprint()
		if fperr != nil {
			fp = "<error generating certificate fingerprint>"
		}

		attrs := []slog.Attr{
			slog.Any("error", err),
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			slog.Any("certVpnNetworks", rc.Networks()),
			slog.String("certFingerprint", fp),
		}
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			attrs = append(attrs, slog.Any("cert", rc))
		}

		f.l.LogAttrs(context.Background(), slog.LevelInfo, "Invalid certificate from host", attrs...)
		return
	}

	if !bytes.Equal(remoteCert.Certificate.PublicKey(), ci.H.PeerStatic()) {
		f.l.Info("public key mismatch between certificate and handshake",
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			slog.Any("cert", remoteCert),
		)
		return
	}

	if remoteCert.Certificate.Version() != ci.myCert.Version() {
		// We started off using the wrong certificate version, lets see if we can match the version that was sent to us
		myCertOtherVersion := cs.getCertificate(remoteCert.Certificate.Version())
		if myCertOtherVersion == nil {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				f.l.Debug("Might be unable to handshake with host due to missing certificate version",
					slog.Any("error", err),
					slog.Any("from", via),
					slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
					slog.Any("cert", remoteCert),
				)
			}
		} else {
			// Record the certificate we are actually using
			ci.myCert = myCertOtherVersion
		}
	}

	if len(remoteCert.Certificate.Networks()) == 0 {
		f.l.Info("No networks in certificate",
			slog.Any("error", err),
			slog.Any("from", via),
			slog.Any("cert", remoteCert),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)
		return
	}

	certName := remoteCert.Certificate.Name()
	certVersion := remoteCert.Certificate.Version()
	fingerprint := remoteCert.Fingerprint
	issuer := remoteCert.Certificate.Issuer()
	vpnNetworks := remoteCert.Certificate.Networks()

	anyVpnAddrsInCommon := false
	vpnAddrs := make([]netip.Addr, len(vpnNetworks))
	for i, network := range vpnNetworks {
		if f.myVpnAddrsTable.Contains(network.Addr()) {
			f.l.Error("Refusing to handshake with myself",
				slog.Any("vpnNetworks", vpnNetworks),
				slog.Any("from", via),
				slog.String("certName", certName),
				slog.Any("certVersion", certVersion),
				slog.String("fingerprint", fingerprint),
				slog.String("issuer", issuer),
				slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)
			return
		}
		vpnAddrs[i] = network.Addr()
		if f.myVpnNetworksTable.Contains(network.Addr()) {
			anyVpnAddrsInCommon = true
		}
	}

	if !via.IsRelayed {
		// We only want to apply the remote allow list for direct tunnels here
		if !f.lightHouse.GetRemoteAllowList().AllowAll(vpnAddrs, via.UdpAddr.Addr()) {
			f.l.Debug("lighthouse.remote_allow_list denied incoming handshake",
				slog.Any("vpnAddrs", vpnAddrs),
				slog.Any("from", via),
			)
			return
		}
	}

	myIndex, err := generateIndex(f.l)
	if err != nil {
		f.l.Error("Failed to generate index",
			slog.Any("error", err),
			slog.Any("vpnAddrs", vpnAddrs),
			slog.Any("from", via),
			slog.String("certName", certName),
			slog.Any("certVersion", certVersion),
			slog.String("fingerprint", fingerprint),
			slog.String("issuer", issuer),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)
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
			relays:         nil,
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}

	msgRxL := f.l.With(
		slog.Any("vpnAddrs", vpnAddrs),
		slog.Any("from", via),
		slog.String("certName", certName),
		slog.Any("certVersion", certVersion),
		slog.String("fingerprint", fingerprint),
		slog.String("issuer", issuer),
		slog.Uint64("initiatorIndex", uint64(hs.Details.InitiatorIndex)),
		slog.Uint64("responderIndex", uint64(hs.Details.ResponderIndex)),
		slog.Uint64("remoteIndex", uint64(h.RemoteIndex)),
		slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
	)

	if anyVpnAddrsInCommon {
		msgRxL.Info("Handshake message received")
	} else {
		//todo warn if not lighthouse or relay?
		msgRxL.Info("Handshake message received, but no vpnNetworks in common.")
	}

	hs.Details.ResponderIndex = myIndex
	hs.Details.Cert = cs.getHandshakeBytes(ci.myCert.Version())
	if hs.Details.Cert == nil {
		msgRxL.Error("Unable to handshake with host because no certificate handshake bytes is available",
			slog.Any("myCertVersion", ci.myCert.Version()),
		)
		return
	}

	hs.Details.CertVersion = uint32(ci.myCert.Version())
	// Update the time in case their clock is way off from ours
	hs.Details.Time = uint64(time.Now().UnixNano())

	hsBytes, err := hs.Marshal()
	if err != nil {
		f.l.Error("Failed to marshal handshake message",
			slog.Any("error", err),
			slog.Any("vpnAddrs", hostinfo.vpnAddrs),
			slog.Any("from", via),
			slog.String("certName", certName),
			slog.Any("certVersion", certVersion),
			slog.String("fingerprint", fingerprint),
			slog.String("issuer", issuer),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)
		return
	}

	nh := header.Encode(make([]byte, header.Len), header.Version, header.Handshake, header.HandshakeIXPSK0, hs.Details.InitiatorIndex, 2)
	msg, dKey, eKey, err := ci.H.WriteMessage(nh, hsBytes)
	if err != nil {
		f.l.Error("Failed to call noise.WriteMessage",
			slog.Any("error", err),
			slog.Any("vpnAddrs", hostinfo.vpnAddrs),
			slog.Any("from", via),
			slog.String("certName", certName),
			slog.Any("certVersion", certVersion),
			slog.String("fingerprint", fingerprint),
			slog.String("issuer", issuer),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)
		return
	} else if dKey == nil || eKey == nil {
		f.l.Error("Noise did not arrive at a key",
			slog.Any("vpnAddrs", hostinfo.vpnAddrs),
			slog.Any("from", via),
			slog.String("certName", certName),
			slog.Any("certVersion", certVersion),
			slog.String("fingerprint", fingerprint),
			slog.String("issuer", issuer),
			slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
		)
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
	if !via.IsRelayed {
		hostinfo.SetRemote(via.UdpAddr)
	}
	hostinfo.buildNetworks(f.myVpnNetworksTable, remoteCert.Certificate)

	existing, err := f.handshakeManager.CheckAndComplete(hostinfo, 0, f)
	if err != nil {
		switch err {
		case ErrAlreadySeen:
			// Update remote if preferred
			if existing.SetRemoteIfPreferred(f.hostMap, via) {
				// Send a test packet to ensure the other side has also switched to
				// the preferred remote
				f.SendMessageToVpnAddr(header.Test, header.TestRequest, vpnAddrs[0], []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			}

			msg = existing.HandshakePacket[2]
			f.messageMetrics.Tx(header.Handshake, header.MessageSubType(msg[1]), 1)
			if !via.IsRelayed {
				err := f.outside.WriteTo(msg, via.UdpAddr)
				if err != nil {
					f.l.Error("Failed to send handshake message",
						slog.Any("vpnAddrs", existing.vpnAddrs),
						slog.Any("from", via),
						slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
						slog.Bool("cached", true),
						slog.Any("error", err),
					)
				} else {
					f.l.Info("Handshake message sent",
						slog.Any("vpnAddrs", existing.vpnAddrs),
						slog.Any("from", via),
						slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
						slog.Bool("cached", true),
					)
				}
				return
			} else {
				if via.relay == nil {
					f.l.Error("Handshake send failed: both addr and via.relay are nil.")
					return
				}
				hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
				f.SendVia(via.relayHI, via.relay, msg, make([]byte, 12), make([]byte, mtu), false)
				f.l.Info("Handshake message sent",
					slog.Any("vpnAddrs", existing.vpnAddrs),
					slog.Any("relay", via.relayHI.vpnAddrs[0]),
					slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
					slog.Bool("cached", true),
				)
				return
			}
		case ErrExistingHostInfo:
			// This means there was an existing tunnel and this handshake was older than the one we are currently based on
			f.l.Info("Handshake too old",
				slog.Any("vpnAddrs", vpnAddrs),
				slog.Any("from", via),
				slog.String("certName", certName),
				slog.Any("certVersion", certVersion),
				slog.Uint64("oldHandshakeTime", existing.lastHandshakeTime),
				slog.Uint64("newHandshakeTime", hostinfo.lastHandshakeTime),
				slog.String("fingerprint", fingerprint),
				slog.String("issuer", issuer),
				slog.Uint64("initiatorIndex", uint64(hs.Details.InitiatorIndex)),
				slog.Uint64("responderIndex", uint64(hs.Details.ResponderIndex)),
				slog.Uint64("remoteIndex", uint64(h.RemoteIndex)),
				slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)

			// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
			f.SendMessageToVpnAddr(header.Test, header.TestRequest, vpnAddrs[0], []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			return
		case ErrLocalIndexCollision:
			// This means we failed to insert because of collision on localIndexId. Just let the next handshake packet retry
			f.l.Error("Failed to add HostInfo due to localIndex collision",
				slog.Any("vpnAddrs", vpnAddrs),
				slog.Any("from", via),
				slog.String("certName", certName),
				slog.Any("certVersion", certVersion),
				slog.String("fingerprint", fingerprint),
				slog.String("issuer", issuer),
				slog.Uint64("initiatorIndex", uint64(hs.Details.InitiatorIndex)),
				slog.Uint64("responderIndex", uint64(hs.Details.ResponderIndex)),
				slog.Uint64("remoteIndex", uint64(h.RemoteIndex)),
				slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
				slog.Uint64("localIndex", uint64(hostinfo.localIndexId)),
				slog.Any("collision", existing.vpnAddrs),
			)
			return
		default:
			// Shouldn't happen, but just in case someone adds a new error type to CheckAndComplete
			// And we forget to update it here
			f.l.Error("Failed to add HostInfo to HostMap",
				slog.Any("error", err),
				slog.Any("vpnAddrs", vpnAddrs),
				slog.Any("from", via),
				slog.String("certName", certName),
				slog.Any("certVersion", certVersion),
				slog.String("fingerprint", fingerprint),
				slog.String("issuer", issuer),
				slog.Uint64("initiatorIndex", uint64(hs.Details.InitiatorIndex)),
				slog.Uint64("responderIndex", uint64(hs.Details.ResponderIndex)),
				slog.Uint64("remoteIndex", uint64(h.RemoteIndex)),
				slog.Any("handshake", m{"stage": 1, "style": "ix_psk0"}),
			)
			return
		}
	}

	// Do the send
	f.messageMetrics.Tx(header.Handshake, header.MessageSubType(msg[1]), 1)
	if !via.IsRelayed {
		err = f.outside.WriteTo(msg, via.UdpAddr)
		log := f.l.With(
			slog.Any("vpnAddrs", vpnAddrs),
			slog.Any("from", via),
			slog.String("certName", certName),
			slog.Any("certVersion", certVersion),
			slog.String("fingerprint", fingerprint),
			slog.String("issuer", issuer),
			slog.Uint64("initiatorIndex", uint64(hs.Details.InitiatorIndex)),
			slog.Uint64("responderIndex", uint64(hs.Details.ResponderIndex)),
			slog.Uint64("remoteIndex", uint64(h.RemoteIndex)),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
		)
		if err != nil {
			log.Error("Failed to send handshake", slog.Any("error", err))
		} else {
			log.Info("Handshake message sent")
		}
	} else {
		if via.relay == nil {
			f.l.Error("Handshake send failed: both addr and via.relay are nil.")
			return
		}
		hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
		// I successfully received a handshake. Just in case I marked this tunnel as 'Disestablished', ensure
		// it's correctly marked as working.
		via.relayHI.relayState.UpdateRelayForByIdxState(via.remoteIdx, Established)
		f.SendVia(via.relayHI, via.relay, msg, make([]byte, 12), make([]byte, mtu), false)
		f.l.Info("Handshake message sent",
			slog.Any("vpnAddrs", vpnAddrs),
			slog.Any("relay", via.relayHI.vpnAddrs[0]),
			slog.String("certName", certName),
			slog.Any("certVersion", certVersion),
			slog.String("fingerprint", fingerprint),
			slog.String("issuer", issuer),
			slog.Uint64("initiatorIndex", uint64(hs.Details.InitiatorIndex)),
			slog.Uint64("responderIndex", uint64(hs.Details.ResponderIndex)),
			slog.Uint64("remoteIndex", uint64(h.RemoteIndex)),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
		)
	}

	f.connectionManager.AddTrafficWatch(hostinfo)

	hostinfo.remotes.RefreshFromHandshake(vpnAddrs)

	// Don't wait for UpdateWorker
	if f.lightHouse.IsAnyLighthouseAddr(vpnAddrs) {
		f.lightHouse.TriggerUpdate()
	}

	return
}

func ixHandshakeStage2(f *Interface, via ViaSender, hh *HandshakeHostInfo, packet []byte, h *header.H) bool {
	if hh == nil {
		// Nothing here to tear down, got a bogus stage 2 packet
		return true
	}

	hh.Lock()
	defer hh.Unlock()

	hostinfo := hh.hostinfo
	if !via.IsRelayed {
		// The vpnAddr we know about is the one we tried to handshake with, use it to apply the remote allow list.
		if !f.lightHouse.GetRemoteAllowList().AllowAll(hostinfo.vpnAddrs, via.UdpAddr.Addr()) {
			f.l.Debug("lighthouse.remote_allow_list denied incoming handshake",
				slog.Any("vpnAddrs", hostinfo.vpnAddrs),
				slog.Any("from", via),
			)
			return false
		}
	}

	ci := hostinfo.ConnectionState
	msg, eKey, dKey, err := ci.H.ReadMessage(nil, packet[header.Len:])
	if err != nil {
		f.l.Error("Failed to call noise.ReadMessage",
			slog.Any("error", err),
			slog.Any("vpnAddrs", hostinfo.vpnAddrs),
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
			slog.Any("header", h),
		)

		// We don't want to tear down the connection on a bad ReadMessage because it could be an attacker trying
		// to DOS us. Every other error condition after should to allow a possible good handshake to complete in the
		// near future
		return false
	} else if dKey == nil || eKey == nil {
		f.l.Error("Noise did not arrive at a key",
			slog.Any("vpnAddrs", hostinfo.vpnAddrs),
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
		)

		// This should be impossible in IX but just in case, if we get here then there is no chance to recover
		// the handshake state machine. Tear it down
		return true
	}

	hs := &NebulaHandshake{}
	err = hs.Unmarshal(msg)
	if err != nil || hs.Details == nil {
		f.l.Error("Failed unmarshal handshake message",
			slog.Any("error", err),
			slog.Any("vpnAddrs", hostinfo.vpnAddrs),
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
		)

		// The handshake state machine is complete, if things break now there is no chance to recover. Tear down and start again
		return true
	}

	rc, err := cert.Recombine(cert.Version(hs.Details.CertVersion), hs.Details.Cert, ci.H.PeerStatic(), ci.Curve())
	if err != nil {
		f.l.Info("Handshake did not contain a certificate",
			slog.Any("error", err),
			slog.Any("from", via),
			slog.Any("vpnAddrs", hostinfo.vpnAddrs),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
		)
		return true
	}

	remoteCert, err := f.pki.GetCAPool().VerifyCertificate(time.Now(), rc)
	if err != nil {
		fp, err := rc.Fingerprint()
		if err != nil {
			fp = "<error generating certificate fingerprint>"
		}

		attrs := []slog.Attr{
			slog.Any("error", err),
			slog.Any("from", via),
			slog.Any("vpnAddrs", hostinfo.vpnAddrs),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
			slog.String("certFingerprint", fp),
			slog.Any("certVpnNetworks", rc.Networks()),
		}
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			attrs = append(attrs, slog.Any("cert", rc))
		}

		f.l.LogAttrs(context.Background(), slog.LevelInfo, "Invalid certificate from host", attrs...)
		return true
	}
	if !bytes.Equal(remoteCert.Certificate.PublicKey(), ci.H.PeerStatic()) {
		f.l.Info("public key mismatch between certificate and handshake",
			slog.Any("from", via),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
			slog.Any("cert", remoteCert),
		)
		return true
	}

	if len(remoteCert.Certificate.Networks()) == 0 {
		f.l.Info("No networks in certificate",
			slog.Any("error", err),
			slog.Any("from", via),
			slog.Any("vpnAddrs", hostinfo.vpnAddrs),
			slog.Any("cert", remoteCert),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
		)
		return true
	}

	vpnNetworks := remoteCert.Certificate.Networks()
	certName := remoteCert.Certificate.Name()
	certVersion := remoteCert.Certificate.Version()
	fingerprint := remoteCert.Fingerprint
	issuer := remoteCert.Certificate.Issuer()

	hostinfo.remoteIndexId = hs.Details.ResponderIndex
	hostinfo.lastHandshakeTime = hs.Details.Time

	// Store their cert and our symmetric keys
	ci.peerCert = remoteCert
	ci.dKey = NewNebulaCipherState(dKey)
	ci.eKey = NewNebulaCipherState(eKey)

	// Make sure the current udpAddr being used is set for responding
	if !via.IsRelayed {
		hostinfo.SetRemote(via.UdpAddr)
	} else {
		hostinfo.relayState.InsertRelayTo(via.relayHI.vpnAddrs[0])
	}

	correctHostResponded := false
	anyVpnAddrsInCommon := false
	vpnAddrs := make([]netip.Addr, len(vpnNetworks))
	for i, network := range vpnNetworks {
		vpnAddrs[i] = network.Addr()
		if f.myVpnNetworksTable.Contains(network.Addr()) {
			anyVpnAddrsInCommon = true
		}
		if hostinfo.vpnAddrs[0] == network.Addr() {
			// todo is it more correct to see if any of hostinfo.vpnAddrs are in the cert? it should have len==1, but one day it might not?
			correctHostResponded = true
		}
	}

	// Ensure the right host responded
	if !correctHostResponded {
		f.l.Info("Incorrect host responded to handshake",
			slog.Any("intendedVpnAddrs", hostinfo.vpnAddrs),
			slog.Any("haveVpnNetworks", vpnNetworks),
			slog.Any("from", via),
			slog.String("certName", certName),
			slog.Any("certVersion", certVersion),
			slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
		)

		// Release our old handshake from pending, it should not continue
		f.handshakeManager.DeleteHostInfo(hostinfo)

		// Create a new hostinfo/handshake for the intended vpn ip
		//TODO is hostinfo.vpnAddrs[0] always the address to use?
		f.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], func(newHH *HandshakeHostInfo) {
			// Block the current used address
			newHH.hostinfo.remotes = hostinfo.remotes
			newHH.hostinfo.remotes.BlockRemote(via)

			f.l.Info("Blocked addresses for handshakes",
				slog.Any("blockedUdpAddrs", newHH.hostinfo.remotes.CopyBlockedRemotes()),
				slog.Any("vpnNetworks", vpnNetworks),
				slog.Any("remotes", newHH.hostinfo.remotes.CopyAddrs(f.hostMap.GetPreferredRanges())),
			)

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
	msgRxL := f.l.With(
		slog.Any("vpnAddrs", vpnAddrs),
		slog.Any("from", via),
		slog.String("certName", certName),
		slog.Any("certVersion", certVersion),
		slog.String("fingerprint", fingerprint),
		slog.String("issuer", issuer),
		slog.Uint64("initiatorIndex", uint64(hs.Details.InitiatorIndex)),
		slog.Uint64("responderIndex", uint64(hs.Details.ResponderIndex)),
		slog.Uint64("remoteIndex", uint64(h.RemoteIndex)),
		slog.Any("handshake", m{"stage": 2, "style": "ix_psk0"}),
		slog.Int64("durationNs", duration),
		slog.Int("sentCachedPackets", len(hh.packetStore)),
	)
	if anyVpnAddrsInCommon {
		msgRxL.Info("Handshake message received")
	} else {
		//todo warn if not lighthouse or relay?
		msgRxL.Info("Handshake message received, but no vpnNetworks in common.")
	}

	// Build up the radix for the firewall if we have subnets in the cert
	hostinfo.vpnAddrs = vpnAddrs
	hostinfo.buildNetworks(f.myVpnNetworksTable, remoteCert.Certificate)

	// Complete our handshake and update metrics, this will replace any existing tunnels for the vpnAddrs here
	f.handshakeManager.Complete(hostinfo, f)
	f.connectionManager.AddTrafficWatch(hostinfo)

	if f.l.Enabled(context.Background(), slog.LevelDebug) {
		hostinfo.logger(f.l).Debug("Sending stored packets",
			slog.Int("count", len(hh.packetStore)),
		)
	}

	if len(hh.packetStore) > 0 {
		nb := make([]byte, 12, 12)
		out := make([]byte, mtu)
		for _, cp := range hh.packetStore {
			cp.callback(cp.messageType, cp.messageSubType, hostinfo, cp.packet, nb, out)
		}
		f.cachedPacketMetrics.sent.Inc(int64(len(hh.packetStore)))
	}

	hostinfo.remotes.RefreshFromHandshake(vpnAddrs)
	f.metricHandshakes.Update(duration)

	// Don't wait for UpdateWorker
	if f.lightHouse.IsAnyLighthouseAddr(vpnAddrs) {
		f.lightHouse.TriggerUpdate()
	}

	return false
}
