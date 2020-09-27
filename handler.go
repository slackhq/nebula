package nebula

func (f *Interface) handleMessagePacket(hostInfo *HostInfo, ci *ConnectionState, addr *udpAddr, header *Header, out []byte, packet []byte, fwPacket *FirewallPacket, nb []byte) {
	if !f.handleEncrypted(ci, addr, header) {
		return
	}

	f.decryptToTun(hostInfo, header.MessageCounter, out, packet, fwPacket, nb)

	f.handleHostRoaming(hostInfo, addr)
	f.connectionManager.In(hostInfo.hostId)
}

func (f *Interface) handleLighthousePacket(hostInfo *HostInfo, ci *ConnectionState, addr *udpAddr, header *Header, out []byte, packet []byte, fwPacket *FirewallPacket, nb []byte) {
	f.messageMetrics.Rx(header.Type, header.Subtype, 1)
	if !f.handleEncrypted(ci, addr, header) {
		return
	}

	d, err := f.decrypt(hostInfo, header.MessageCounter, out, packet, header, nb)
	if err != nil {
		hostInfo.logger().WithError(err).WithField("udpAddr", addr).
			WithField("packet", packet).
			Error("Failed to decrypt lighthouse packet")

		//TODO: maybe after build 64 is out? 06/14/2018 - NB
		//f.sendRecvError(net.Addr(addr), header.RemoteIndex)
		return
	}

	f.lightHouse.HandleRequest(addr, hostInfo.hostId, d, hostInfo.GetCert(), f)

	f.handleHostRoaming(hostInfo, addr)
	f.connectionManager.In(hostInfo.hostId)
}

func (f *Interface) handleTestPacket(hostInfo *HostInfo, ci *ConnectionState, addr *udpAddr, header *Header, out []byte, packet []byte, fwPacket *FirewallPacket, nb []byte) {
	f.messageMetrics.Rx(header.Type, header.Subtype, 1)
	if !f.handleEncrypted(ci, addr, header) {
		return
	}

	d, err := f.decrypt(hostInfo, header.MessageCounter, out, packet, header, nb)
	if err != nil {
		hostInfo.logger().WithError(err).WithField("udpAddr", addr).
			WithField("packet", packet).
			Error("Failed to decrypt test packet")

		//TODO: maybe after build 64 is out? 06/14/2018 - NB
		//f.sendRecvError(net.Addr(addr), header.RemoteIndex)
		return
	}

	if header.Subtype == testRequest {
		// This testRequest might be from TryPromoteBest, so we should roam
		// to the new IP address before responding
		f.handleHostRoaming(hostInfo, addr)
		f.send(test, testReply, ci, hostInfo, hostInfo.remote, d, nb, out)
	}

	f.handleHostRoaming(hostInfo, addr)
	f.connectionManager.In(hostInfo.hostId)
}

func (f *Interface) handleHandshakePacket(hostInfo *HostInfo, ci *ConnectionState, addr *udpAddr, header *Header, out []byte, packet []byte, fwPacket *FirewallPacket, nb []byte) {
	f.messageMetrics.Rx(header.Type, header.Subtype, 1)
	HandleIncomingHandshake(f, addr, packet, header, hostInfo)
}

func (f *Interface) handleRecvErrorPacket(hostInfo *HostInfo, ci *ConnectionState, addr *udpAddr, header *Header, out []byte, packet []byte, fwPacket *FirewallPacket, nb []byte) {
	f.messageMetrics.Rx(header.Type, header.Subtype, 1)
	// TODO: Remove this with recv_error deprecation
	f.handleRecvError(addr, header)
}

func (f *Interface) handleCloseTunnelPacket(hostInfo *HostInfo, ci *ConnectionState, addr *udpAddr, header *Header, out []byte, packet []byte, fwPacket *FirewallPacket, nb []byte) {
	f.messageMetrics.Rx(header.Type, header.Subtype, 1)
	if !f.handleEncrypted(ci, addr, header) {
		return
	}

	hostInfo.logger().WithField("udpAddr", addr).
		Info("Close tunnel received, tearing down.")

	f.closeTunnel(hostInfo)
}
