package cidr

import (
	"net"

	"github.com/slackhq/nebula/iputil"
)

type Node[T any] struct {
	left     *Node[T]
	right    *Node[T]
	parent   *Node[T]
	hasValue bool
	value    T
}

type entry[T any] struct {
	CIDR  *net.IPNet
	Value T
}

type Tree4[T any] struct {
	root *Node[T]
	list []entry[T]
}

const (
	startbit = iputil.VpnIp(0x80000000)
)

func NewTree4[T any]() *Tree4[T] {
	tree := new(Tree4[T])
	tree.root = &Node[T]{}
	tree.list = []entry[T]{}
	return tree
}

func (tree *Tree4[T]) AddCIDR(cidr *net.IPNet, val T) {
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
		addCIDR := cidr.String()
		for i, v := range tree.list {
			if addCIDR == v.CIDR.String() {
				tree.list = append(tree.list[:i], tree.list[i+1:]...)
				break
			}
		}

		tree.list = append(tree.list, entry[T]{CIDR: cidr, Value: val})
		node.value = val
		node.hasValue = true
		return
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

	// Final node marks our cidr, set the value
	node.value = val
	node.hasValue = true
	tree.list = append(tree.list, entry[T]{CIDR: cidr, Value: val})
}

// Contains finds the first match, which may be the least specific
func (tree *Tree4[T]) Contains(ip iputil.VpnIp) (ok bool, value T) {
	bit := startbit
	node := tree.root

	for node != nil {
		if node.hasValue {
			return true, node.value
		}

		if ip&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}

		bit >>= 1

	}

	return false, value
}

// MostSpecificContains finds the most specific match
func (tree *Tree4[T]) MostSpecificContains(ip iputil.VpnIp) (ok bool, value T) {
	bit := startbit
	node := tree.root

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

// Match finds the most specific match
// TODO this is exact match
func (tree *Tree4[T]) Match(ip iputil.VpnIp) (ok bool, value T) {
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
		ok = true
	}
	return ok, value
}

// List will return all CIDRs and their current values. Do not modify the contents!
func (tree *Tree4[T]) List() []entry[T] {
	return tree.list
}
