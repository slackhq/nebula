package nebula

import (
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/udp"
)

// NOISE IX Handshakes

// This function constructs a handshake packet, but does not actually send it
// Sending is done by the handshake manager
func ixHandshakeStage0(f *Interface, vpnIp iputil.VpnIp, hostinfo *HostInfo) {
	// This queries the lighthouse if we don't know a remote for the host
	// We do it here to provoke the lighthouse to preempt our timer wheel and trigger the stage 1 packet to send
	// more quickly, effect is a quicker handshake.
	if hostinfo.remote == nil {
		f.lightHouse.QueryServer(vpnIp, f)
	}

	err := f.handshakeManager.AddIndexHostInfo(hostinfo)
	if err != nil {
		f.l.WithError(err).WithField("vpnIp", vpnIp).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to generate index")
		return
	}

	ci := hostinfo.ConnectionState

	hsProto := &NebulaHandshakeDetails{
		InitiatorIndex: hostinfo.localIndexId,
		Time:           uint64(time.Now().UnixNano()),
		Cert:           ci.certState.rawCertificateNoKey,
	}

	hsBytes := []byte{}

	hs := &NebulaHandshake{
		Details: hsProto,
	}
	hsBytes, err = hs.Marshal()

	if err != nil {
		f.l.WithError(err).WithField("vpnIp", vpnIp).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to marshal handshake message")
		return
	}

	h := header.Encode(make([]byte, header.Len), header.Version, header.Handshake, header.HandshakeIXPSK0, 0, 1)
	atomic.AddUint64(&ci.atomicMessageCounter, 1)

	msg, _, _, err := ci.H.WriteMessage(h, hsBytes)
	if err != nil {
		f.l.WithError(err).WithField("vpnIp", vpnIp).
			WithField("handshake", m{"stage": 0, "style": "ix_psk0"}).Error("Failed to call noise.WriteMessage")
		return
	}

	// We are sending handshake packet 1, so we don't expect to receive
	// handshake packet 1 from the responder
	ci.window.Update(f.l, 1)

	hostinfo.HandshakePacket[0] = msg
	hostinfo.HandshakeReady = true
	hostinfo.handshakeStart = time.Now()
}

func ixHandshakeStage1(f *Interface, addr *udp.Addr, via interface{}, packet []byte, h *header.H) {
	ci := f.newConnectionState(f.l, false, noise.HandshakeIX, []byte{}, 0)
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
	/*
		l.Debugln("GOT INDEX: ", hs.Details.InitiatorIndex)
	*/
	if err != nil || hs.Details == nil {
		f.l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed unmarshal handshake message")
		return
	}

	remoteCert, err := RecombineCertAndValidate(ci.H, hs.Details.Cert, f.caPool)
	if err != nil {
		f.l.WithError(err).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).WithField("cert", remoteCert).
			Info("Invalid certificate from host")
		return
	}
	vpnIp := iputil.Ip2VpnIp(remoteCert.Details.Ips[0].IP)
	certName := remoteCert.Details.Name
	fingerprint, _ := remoteCert.Sha256Sum()
	issuer := remoteCert.Details.Issuer

	if vpnIp == f.myVpnIp {
		f.l.WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("issuer", issuer).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Refusing to handshake with myself")
		return
	}

	if addr != nil {
		if !f.lightHouse.GetRemoteAllowList().Allow(vpnIp, addr.IP) {
			f.l.WithField("vpnIp", vpnIp).WithField("udpAddr", addr).Debug("lighthouse.remote_allow_list denied incoming handshake")
			return
		}
	}

	myIndex, err := generateIndex(f.l)
	if err != nil {
		f.l.WithError(err).WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
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
		vpnIp:             vpnIp,
		HandshakePacket:   make(map[uint8][]byte, 0),
		lastHandshakeTime: hs.Details.Time,
		relays:            map[iputil.VpnIp]struct{}{},
		relayForByIp:      map[iputil.VpnIp]*Relay{},
		relayForByIdx:     map[uint32]*Relay{},
	}

	hostinfo.Lock()
	defer hostinfo.Unlock()

	f.l.WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
		WithField("certName", certName).
		WithField("fingerprint", fingerprint).
		WithField("issuer", issuer).
		WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
		WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
		Info("Handshake message received")

	hs.Details.ResponderIndex = myIndex
	hs.Details.Cert = ci.certState.rawCertificateNoKey
	// Update the time in case their clock is way off from ours
	hs.Details.Time = uint64(time.Now().UnixNano())

	hsBytes, err := hs.Marshal()
	if err != nil {
		f.l.WithError(err).WithField("vpnIp", hostinfo.vpnIp).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("issuer", issuer).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to marshal handshake message")
		return
	}

	nh := header.Encode(make([]byte, header.Len), header.Version, header.Handshake, header.HandshakeIXPSK0, hs.Details.InitiatorIndex, 2)
	msg, dKey, eKey, err := ci.H.WriteMessage(nh, hsBytes)
	if err != nil {
		f.l.WithError(err).WithField("vpnIp", hostinfo.vpnIp).WithField("udpAddr", addr).
			WithField("certName", certName).
			WithField("fingerprint", fingerprint).
			WithField("issuer", issuer).
			WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).Error("Failed to call noise.WriteMessage")
		return
	} else if dKey == nil || eKey == nil {
		f.l.WithField("vpnIp", hostinfo.vpnIp).WithField("udpAddr", addr).
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

	hostinfo.remotes = f.lightHouse.QueryCache(vpnIp)
	hostinfo.SetRemote(addr)
	hostinfo.CreateRemoteCIDR(remoteCert)

	// Only overwrite existing record if we should win the handshake race
	overwrite := vpnIp > f.myVpnIp
	existing, err := f.handshakeManager.CheckAndComplete(hostinfo, 0, overwrite, f)
	if err != nil {
		switch err {
		case ErrAlreadySeen:
			// Update remote if preferred (Note we have to switch to locking
			// the existing hostinfo, and then switch back so the defer Unlock
			// higher in this function still works)
			hostinfo.Unlock()
			existing.Lock()
			// Update remote if preferred
			if existing.SetRemoteIfPreferred(f.hostMap, addr) {
				// Send a test packet to ensure the other side has also switched to
				// the preferred remote
				f.SendMessageToVpnIp(header.Test, header.TestRequest, vpnIp, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			}
			existing.Unlock()
			hostinfo.Lock()

			msg = existing.HandshakePacket[2]
			f.messageMetrics.Tx(header.Handshake, header.MessageSubType(msg[1]), 1)
			if addr != nil {
				err := f.outside.WriteTo(msg, addr)
				if err != nil {
					f.l.WithField("vpnIp", existing.vpnIp).WithField("udpAddr", addr).
						WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("cached", true).
						WithError(err).Error("Failed to send handshake message")
				} else {
					f.l.WithField("vpnIp", existing.vpnIp).WithField("udpAddr", addr).
						WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("cached", true).
						Info("Handshake message sent")
				}
				return
			} else {
				via2 := via.(*ViaSender)
				if via2 == nil {
					f.l.Error("BRAD: Both addr and via are nil. Can't send anything.")
					return
				}
				f.l.Infof("BRAD: ErrAlreadySeen ix_handshake_stage1 Send response via relay %v", via2.relayHI.vpnIp)
				hostinfo.relays[via2.relayHI.vpnIp] = struct{}{}
				f.SendVia(via2.relayHI, via2.remoteIdx, msg, make([]byte, 12), make([]byte, mtu), false)
				return
			}
		case ErrExistingHostInfo:
			// This means there was an existing tunnel and this handshake was older than the one we are currently based on
			f.l.WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("oldHandshakeTime", existing.lastHandshakeTime).
				WithField("newHandshakeTime", hostinfo.lastHandshakeTime).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				Info("Handshake too old")

			// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
			f.SendMessageToVpnIp(header.Test, header.TestRequest, vpnIp, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			return
		case ErrLocalIndexCollision:
			// This means we failed to insert because of collision on localIndexId. Just let the next handshake packet retry
			f.l.WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				WithField("localIndex", hostinfo.localIndexId).WithField("collision", existing.vpnIp).
				Error("Failed to add HostInfo due to localIndex collision")
			return
		case ErrExistingHandshake:
			// We have a race where both parties think they are an initiator and this tunnel lost, let the other one finish
			f.l.WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 1, "style": "ix_psk0"}).
				Error("Prevented a pending handshake race")
			return
		default:
			// Shouldn't happen, but just in case someone adds a new error type to CheckAndComplete
			// And we forget to update it here
			f.l.WithError(err).WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
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
	if addr != nil {
		err = f.outside.WriteTo(msg, addr)
		if err != nil {
			f.l.WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
				WithError(err).Error("Failed to send handshake")
		} else {
			f.l.WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
				WithField("certName", certName).
				WithField("fingerprint", fingerprint).
				WithField("issuer", issuer).
				WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
				WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
				WithField("sentCachedPackets", len(hostinfo.packetStore)).
				Info("Handshake message sent")
		}
	} else {
		via2 := via.(*ViaSender)
		if via2 == nil {
			f.l.Error("BRAD: Both addr and via are nil. Can't send anything.")
			return
		}
		f.l.Infof("BRAD: ix_handshake_stage1 Send response via relay %v", via2.relayHI.vpnIp)
		hostinfo.relays[via2.relayHI.vpnIp] = struct{}{}
		f.SendVia(via2.relayHI, via2.remoteIdx, msg, make([]byte, 12), make([]byte, mtu), false)
	}

	hostinfo.handshakeComplete(f.l, f.cachedPacketMetrics)

	return
}

func ixHandshakeStage2(f *Interface, addr *udp.Addr, via interface{}, hostinfo *HostInfo, packet []byte, h *header.H) bool {
	if hostinfo == nil {
		// Nothing here to tear down, got a bogus stage 2 packet
		return true
	}

	hostinfo.Lock()
	defer hostinfo.Unlock()

	if addr != nil {
		if !f.lightHouse.GetRemoteAllowList().Allow(hostinfo.vpnIp, addr.IP) {
			f.l.WithField("vpnIp", hostinfo.vpnIp).WithField("udpAddr", addr).Debug("lighthouse.remote_allow_list denied incoming handshake")
			return false
		}
	}

	ci := hostinfo.ConnectionState
	if ci.ready {
		f.l.WithField("vpnIp", hostinfo.vpnIp).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("header", h).
			Info("Handshake is already complete")

		// Update remote if preferred
		if addr != nil {
			if hostinfo.SetRemoteIfPreferred(f.hostMap, addr) {
				// Send a test packet to ensure the other side has also switched to
				// the preferred remote
				f.SendMessageToVpnIp(header.Test, header.TestRequest, hostinfo.vpnIp, []byte(""), make([]byte, 12, 12), make([]byte, mtu))
			}
		}

		// We already have a complete tunnel, there is nothing that can be done by processing further stage 1 packets
		return false
	}

	msg, eKey, dKey, err := ci.H.ReadMessage(nil, packet[header.Len:])
	if err != nil {
		f.l.WithError(err).WithField("vpnIp", hostinfo.vpnIp).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).WithField("header", h).
			Error("Failed to call noise.ReadMessage")

		// We don't want to tear down the connection on a bad ReadMessage because it could be an attacker trying
		// to DOS us. Every other error condition after should to allow a possible good handshake to complete in the
		// near future
		return false
	} else if dKey == nil || eKey == nil {
		f.l.WithField("vpnIp", hostinfo.vpnIp).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Error("Noise did not arrive at a key")

		// This should be impossible in IX but just in case, if we get here then there is no chance to recover
		// the handshake state machine. Tear it down
		return true
	}

	hs := &NebulaHandshake{}
	err = hs.Unmarshal(msg)
	if err != nil || hs.Details == nil {
		f.l.WithError(err).WithField("vpnIp", hostinfo.vpnIp).WithField("udpAddr", addr).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).Error("Failed unmarshal handshake message")

		// The handshake state machine is complete, if things break now there is no chance to recover. Tear down and start again
		return true
	}

	remoteCert, err := RecombineCertAndValidate(ci.H, hs.Details.Cert, f.caPool)
	if err != nil {
		f.l.WithError(err).WithField("vpnIp", hostinfo.vpnIp).WithField("udpAddr", addr).
			WithField("cert", remoteCert).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Error("Invalid certificate from host")

		// The handshake state machine is complete, if things break now there is no chance to recover. Tear down and start again
		return true
	}

	vpnIp := iputil.Ip2VpnIp(remoteCert.Details.Ips[0].IP)
	certName := remoteCert.Details.Name
	fingerprint, _ := remoteCert.Sha256Sum()
	issuer := remoteCert.Details.Issuer

	// Ensure the right host responded
	if vpnIp != hostinfo.vpnIp {
		f.l.WithField("intendedVpnIp", hostinfo.vpnIp).WithField("haveVpnIp", vpnIp).
			WithField("udpAddr", addr).WithField("certName", certName).
			WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
			Info("Incorrect host responded to handshake")

		// Release our old handshake from pending, it should not continue
		f.handshakeManager.pendingHostMap.DeleteHostInfo(hostinfo)

		// Create a new hostinfo/handshake for the intended vpn ip
		//TODO: this adds it to the timer wheel in a way that aggressively retries
		newHostInfo := f.getOrHandshake(hostinfo.vpnIp)
		newHostInfo.Lock()

		// Block the current used address
		newHostInfo.remotes = hostinfo.remotes
		newHostInfo.remotes.BlockRemote(addr)

		// Get the correct remote list for the host we did handshake with
		hostinfo.remotes = f.lightHouse.QueryCache(vpnIp)

		f.l.WithField("blockedUdpAddrs", newHostInfo.remotes.CopyBlockedRemotes()).WithField("vpnIp", vpnIp).
			WithField("remotes", newHostInfo.remotes.CopyAddrs(f.hostMap.preferredRanges)).
			Info("Blocked addresses for handshakes")

		// Swap the packet store to benefit the original intended recipient
		hostinfo.ConnectionState.queueLock.Lock()
		newHostInfo.packetStore = hostinfo.packetStore
		hostinfo.packetStore = []*cachedPacket{}
		hostinfo.ConnectionState.queueLock.Unlock()

		// Finally, put the correct vpn ip in the host info, tell them to close the tunnel, and return true to tear down
		hostinfo.vpnIp = vpnIp
		f.sendCloseTunnel(hostinfo)
		newHostInfo.Unlock()

		return true
	}

	// Mark packet 2 as seen so it doesn't show up as missed
	ci.window.Update(f.l, 2)

	duration := time.Since(hostinfo.handshakeStart).Nanoseconds()
	f.l.WithField("vpnIp", vpnIp).WithField("udpAddr", addr).
		WithField("certName", certName).
		WithField("fingerprint", fingerprint).
		WithField("issuer", issuer).
		WithField("initiatorIndex", hs.Details.InitiatorIndex).WithField("responderIndex", hs.Details.ResponderIndex).
		WithField("remoteIndex", h.RemoteIndex).WithField("handshake", m{"stage": 2, "style": "ix_psk0"}).
		WithField("durationNs", duration).
		WithField("sentCachedPackets", len(hostinfo.packetStore)).
		Info("Handshake message received")

	hostinfo.remoteIndexId = hs.Details.ResponderIndex
	hostinfo.lastHandshakeTime = hs.Details.Time

	// Store their cert and our symmetric keys
	ci.peerCert = remoteCert
	ci.dKey = NewNebulaCipherState(dKey)
	ci.eKey = NewNebulaCipherState(eKey)

	// Make sure the current udpAddr being used is set for responding
	if addr != nil {
		hostinfo.SetRemote(addr)
	} else {
		via2 := via.(*ViaSender)
		hostinfo.relays[via2.relayHI.vpnIp] = struct{}{}
	}

	// Build up the radix for the firewall if we have subnets in the cert
	hostinfo.CreateRemoteCIDR(remoteCert)

	// Complete our handshake and update metrics, this will replace any existing tunnels for this vpnIp
	//TODO: Complete here does not do a race avoidance, it will just take the new tunnel. Is this ok?
	f.handshakeManager.Complete(hostinfo, f)
	hostinfo.handshakeComplete(f.l, f.cachedPacketMetrics)
	f.metricHandshakes.Update(duration)

	return false
}
