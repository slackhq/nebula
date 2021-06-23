package udp

import (
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
)

//TODO: The items in this file belong in their own packages but doing that in a single PR is a nightmare

type EncWriter interface {
	SendMessageToVpnIp(t header.MessageType, st header.MessageSubType, vpnIp iputil.VpnIp, p, nb, out []byte)
}

type LightHouseHandlerFunc func(rAddr *Addr, vpnIp iputil.VpnIp, p []byte, w EncWriter)
