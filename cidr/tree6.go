package cidr

import (
	"net"

	"github.com/slackhq/nebula/iputil"
)

const startbit6 = uint64(1 << 63)

type Tree6[T any] struct {
	root4 *Node[T]
	root6 *Node[T]
}

func NewTree6[T any]() *Tree6[T] {
	tree := new(Tree6[T])
	tree.root4 = &Node[T]{}
	tree.root6 = &Node[T]{}
	return tree
}

func (tree *Tree6[T]) AddCIDR(cidr *net.IPNet, val T) {
	var node, next *Node[T]

	cidrIP, ipv4 := isIPV4(cidr.IP)
	if ipv4 {
		node = tree.root4
		next = tree.root4

	} else {
		node = tree.root6
		next = tree.root6
	}

	for i := 0; i < len(cidrIP); i += 4 {
		ip := iputil.Ip2VpnIp(cidrIP[i : i+4])
		mask := iputil.Ip2VpnIp(cidr.Mask[i : i+4])
		bit := startbit

		// Find our last ancestor in the tree
		for bit&mask != 0 {
			if ip&bit != 0 {
				next = node.right
			} else {
				next = node.left
			}

			if next == nil {
				break
			}

			bit = bit >> 1
			node = next
		}

		// Build up the rest of the tree we don't already have
		for bit&mask != 0 {
			next = &Node[T]{}
			next.parent = node

			if ip&bit != 0 {
				node.right = next
			} else {
				node.left = next
			}

			bit >>= 1
			node = next
		}
	}

	// Final node marks our cidr, set the value
	node.value = val
	node.hasValue = true
}

// Finds the most specific match
func (tree *Tree6[T]) MostSpecificContains(ip net.IP) (ok bool, value T) {
	var node *Node[T]

	wholeIP, ipv4 := isIPV4(ip)
	if ipv4 {
		node = tree.root4
	} else {
		node = tree.root6
	}

	for i := 0; i < len(wholeIP); i += 4 {
		ip := iputil.Ip2VpnIp(wholeIP[i : i+4])
		bit := startbit

		for node != nil {
			if node.hasValue {
				value = node.value
				ok = true
			}

			if bit == 0 {
				break
			}

			if ip&bit != 0 {
				node = node.right
			} else {
				node = node.left
			}

			bit >>= 1
		}
	}

	return ok, value
}

func (tree *Tree6[T]) MostSpecificContainsIpV4(ip iputil.VpnIp) (ok bool, value T) {
	bit := startbit
	node := tree.root4

	for node != nil {
		if node.hasValue {
			value = node.value
			ok = true
		}

		if ip&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}

		bit >>= 1
	}

	return ok, value
}

func (tree *Tree6[T]) MostSpecificContainsIpV6(hi, lo uint64) (ok bool, value T) {
	ip := hi
	node := tree.root6

	for i := 0; i < 2; i++ {
		bit := startbit6

		for node != nil {
			if node.hasValue {
				value = node.value
				ok = true
			}

			if bit == 0 {
				break
			}

			if ip&bit != 0 {
				node = node.right
			} else {
				node = node.left
			}

			bit >>= 1
		}

		ip = lo
	}

	return ok, value
}

func isIPV4(ip net.IP) (net.IP, bool) {
	if len(ip) == net.IPv4len {
		return ip, true
	}

	if len(ip) == net.IPv6len && isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff {
		return ip[12:16], true
	}

	return ip, false
}

func isZeros(p net.IP) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
}
