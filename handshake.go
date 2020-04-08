package nebula

const (
	handshakeIXPSK0 = 0
	handshakeXXPSK0 = 1
)

func HandleIncomingHandshake(f *Interface, addr *udpAddr, packet []byte, h *Header, hostinfo *HostInfo) {
	newHostinfo, _ := f.handshakeManager.QueryIndex(h.RemoteIndex)
	//TODO: For stage 1 we won't have hostinfo yet but stage 2 and above would require it, this check may be helpful in those cases
	//if err != nil {
	//	l.WithError(err).WithField("udpAddr", addr).Error("Error while finding host info for handshake message")
	//	return
	//}

	if !f.lightHouse.remoteAllowList.Allow(udp2ipInt(addr)) {
		l.WithField("udpAddr", addr).Debug("lighthouse.remote_allow_list denied incoming handshake")
		return
	}

	tearDown := false
	switch h.Subtype {
	case handshakeIXPSK0:
		switch h.MessageCounter {
		case 1:
			tearDown = ixHandshakeStage1(f, addr, newHostinfo, packet, h)
		case 2:
			tearDown = ixHandshakeStage2(f, addr, newHostinfo, packet, h)
		}
	}

	if tearDown && newHostinfo != nil {
		f.handshakeManager.DeleteIndex(newHostinfo.localIndexId)
		f.handshakeManager.DeleteVpnIP(newHostinfo.hostId)
	}
}
