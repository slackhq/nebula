package udp

import (
	"net/netip"
)

//TODO: The items in this file belong in their own packages but doing that in a single PR is a nightmare

// TODO: IPV6-WORK this can likely be removed now
type LightHouseHandlerFunc func(rAddr netip.AddrPort, vpnIp netip.Addr, p []byte)
