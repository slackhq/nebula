package nebula

import (
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/udp"
)

func HandleIncomingHandshake(f *Interface, addr *udp.Addr, packet []byte, h *header.H, hostinfo *HostInfo) {
	// First remote allow list check before we know the vpnIp
	if !f.lightHouse.GetRemoteAllowList().AllowUnknownVpnIp(addr.IP) {
		f.l.WithField("udpAddr", addr).Debug("lighthouse.remote_allow_list denied incoming handshake")
		return
	}

	switch h.Subtype {
	case header.HandshakeIXPSK0:
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
