package nebula

import (
	"encoding/binary"
	"fmt"
	"net"
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
	startbit = uint32(0x80000000)
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

	ip := ip2int(cidr.IP)
	mask := ip2int(cidr.Mask)

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
func (tree *CIDRTree) Contains(ip uint32) (value interface{}) {
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
func (tree *CIDRTree) MostSpecificContains(ip uint32) (value interface{}) {
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
func (tree *CIDRTree) Match(ip uint32) (value interface{}) {
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

// A helper type to avoid converting to IP when logging
type IntIp uint32

func (ip IntIp) String() string {
	return fmt.Sprintf("%v", int2ip(uint32(ip)))
}

func (ip IntIp) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", int2ip(uint32(ip)).String())), nil
}

func ip2int(ip []byte) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
