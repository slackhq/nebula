package udp

import (
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
)

const MTU = 9001

type EncReader func(
	addr *Addr,
	via interface{},
	out []byte,
	packet []byte,
	header *header.H,
	fwPacket *firewall.Packet,
	lhh LightHouseHandlerFunc,
	nb []byte,
	q int,
	localCache firewall.ConntrackCache,
)
