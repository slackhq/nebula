package nebula

import (
	"net"

	"github.com/slackhq/nebula/iputil"
)

type CIDRNode struct {
	left   *CIDRNode
	right  *CIDRNode
	parent *CIDRNode
	value  interface{}
}

type CIDRTree struct {
	root *CIDRNode
}

const (
	startbit = iputil.VpnIp(0x80000000)
)

func NewCIDRTree() *CIDRTree {
	tree := new(CIDRTree)
	tree.root = &CIDRNode{}
	return tree
}

func (tree *CIDRTree) AddCIDR(cidr *net.IPNet, val interface{}) {
	bit := startbit
	node := tree.root
	next := tree.root

	ip := iputil.Ip2VpnIp(cidr.IP)
	mask := iputil.Ip2VpnIp(cidr.Mask)

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

	// We already have this range so update the value
	if next != nil {
		node.value = val
		return
	}

	// Build up the rest of the tree we don't already have
	for bit&mask != 0 {
		next = &CIDRNode{}
		next.parent = node

		if ip&bit != 0 {
			node.right = next
		} else {
			node.left = next
		}

		bit >>= 1
		node = next
	}

	// Final node marks our cidr, set the value
	node.value = val
}

// Finds the first match, which may be the least specific
func (tree *CIDRTree) Contains(ip iputil.VpnIp) (value interface{}) {
	bit := startbit
	node := tree.root

	for node != nil {
		if node.value != nil {
			return node.value
		}

		if ip&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}

		bit >>= 1

	}

	return value
}

// Finds the most specific match
func (tree *CIDRTree) MostSpecificContains(ip iputil.VpnIp) (value interface{}) {
	bit := startbit
	node := tree.root

	for node != nil {
		if node.value != nil {
			value = node.value
		}

		if ip&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}

		bit >>= 1
	}

	return value
}

// Finds the most specific match
func (tree *CIDRTree) Match(ip iputil.VpnIp) (value interface{}) {
	bit := startbit
	node := tree.root
	lastNode := node

	for node != nil {
		lastNode = node
		if ip&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}

		bit >>= 1
	}

	if bit == 0 && lastNode != nil {
		value = lastNode.value
	}
	return value
}
