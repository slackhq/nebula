//go:build e2e_testing
// +build e2e_testing

package nebula

// This file contains functions used to export information to the e2e testing framework

import (
	"net/netip"
)

func (i *HostInfo) GetVpnAddrs() []netip.Addr {
	return i.vpnAddrs
}

func (i *HostInfo) GetLocalIndex() uint32 {
	return i.localIndexId
}

func (i *HostInfo) GetRemoteIndex() uint32 {
	return i.remoteIndexId
}

func (i *HostInfo) GetRelayState() *RelayState {
	return &i.relayState
}
