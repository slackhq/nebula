package cidr

import (
	"net"

	"github.com/slackhq/nebula/iputil"
)

type Node struct {
	left   *Node
	right  *Node
	parent *Node
	value  interface{}
}

type entry struct {
	CIDR  *net.IPNet
	Value *interface{}
}

type Tree4 struct {
	root *Node
	list []entry
}

const (
	startbit = iputil.VpnIp(0x80000000)
)

func NewTree4() *Tree4 {
	tree := new(Tree4)
	tree.root = &Node{}
	tree.list = []entry{}
	return tree
}

func (tree *Tree4) AddCIDR(cidr *net.IPNet, val interface{}) {
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
		next = &Node{}
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
	tree.list = append(tree.list, entry{CIDR: cidr, Value: &val})
}

// Contains finds the first match, which may be the least specific
func (tree *Tree4) Contains(ip iputil.VpnIp) (value interface{}) {
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

// MostSpecificContains finds the most specific match
func (tree *Tree4) MostSpecificContains(ip iputil.VpnIp) (value interface{}) {
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

// Match finds the most specific match
func (tree *Tree4) Match(ip iputil.VpnIp) (value interface{}) {
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

// List will return all CIDRs and their current values. Do not modify the contents!
func (tree *Tree4) List() []entry {
	return tree.list
}
