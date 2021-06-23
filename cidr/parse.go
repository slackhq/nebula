package cidr

import "net"

// Parse is a convenience function that returns only the IPNet
// This function ignores errors since it is primarily a test helper, the result could be nil
func Parse(s string) *net.IPNet {
	_, c, _ := net.ParseCIDR(s)
	return c
}
