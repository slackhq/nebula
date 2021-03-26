package nebula

const (
	handshakeIXPSK0 = 0
	handshakeXXPSK0 = 1
)

func HandleIncomingHandshake(f *Interface, addr *udpAddr, packet []byte, h *Header, hostinfo *HostInfo) {
	if !f.lightHouse.remoteAllowList.Allow(addr.IP) {
		f.l.WithField("udpAddr", addr).Debug("lighthouse.remote_allow_list denied incoming handshake")
		return
	}

	switch h.Subtype {
	case handshakeIXPSK0:
		switch h.MessageCounter {
		case 1:
			ixHandshakeStage1(f, addr, packet, h)
		case 2:
			newHostinfo, _ := f.handshakeManager.QueryIndex(h.RemoteIndex)
			tearDown := ixHandshakeStage2(f, addr, newHostinfo, packet, h)
			if tearDown && newHostinfo != nil {
				f.handshakeManager.DeleteHostInfo(newHostinfo)
			}
		}
	}

}
