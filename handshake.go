package nebula

const (
	handshakeIXPSK0 = 0
	handshakeXXPSK0 = 1
)

func HandleIncomingHandshake(f *Interface, addr *udpAddr, packet []byte, h *Header) {
	if !f.lightHouse.remoteAllowList.Allow(addr.IP) {
		l.WithField("udpAddr", addr).Debug("lighthouse.remote_allow_list denied incoming handshake")
		return
	}

	switch h.Subtype {
	case handshakeIXPSK0:
		switch h.MessageCounter {
		case 1:
			ixHandshakeStage1(f, addr, packet, h, f.outside.WriteTo)
		case 2:
			hostInfo, _ := f.handshakeManager.QueryIndex(h.RemoteIndex)
			tearDown := ixHandshakeStage2(f, addr, hostInfo, packet, h)
			if tearDown && hostInfo != nil {
				f.handshakeManager.pendingHostMap.DeleteHostInfo(hostInfo)
			}
		}
	}

}
