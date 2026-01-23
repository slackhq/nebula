package firewall

import (
	"net/netip"
	"time"
)

type Event struct {
	Packet Packet         `json:"packet,omitempty"`
	At     time.Time      `json:"at,omitempty"`
	Remote netip.AddrPort `json:"remote,omitempty"`
	//todo cert info?
	//todo connection indexes?
	//todo underlay info would actually be amazing, for inbounds
}
