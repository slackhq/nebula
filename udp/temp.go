package udp

import (
	"github.com/slackhq/nebula/iputil"
)

//TODO: The items in this file belong in their own packages but doing that in a single PR is a nightmare

type LightHouseHandlerFunc func(rAddr *Addr, vpnIp iputil.VpnIp, p []byte)
