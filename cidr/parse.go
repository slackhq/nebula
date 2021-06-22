package cidr

import "net"

func Parse(s string) *net.IPNet {
	_, c, _ := net.ParseCIDR(s)
	return c
}
