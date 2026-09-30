package firewall

import (
	"iter"
	"math/bits"
)

// ruleSet is a set of rule ids, stored as a bitset. s[i] holds ids i*8 through i*8+7, one per bit.
// Bytes rather than words keep a set to the size the rule count needs, which matters when there is a set for
// every port number.
type ruleSet []uint8

// ruleSetLen returns the length of a ruleSet that can hold ids below n.
func ruleSetLen(n int) int {
	return (n + 7) / 8
}

// newRuleSet returns an empty set that can hold ids below idLimit.
func newRuleSet(idLimit int) ruleSet {
	return make(ruleSet, ruleSetLen(idLimit))
}

// add puts id in s.
func (s ruleSet) add(id int) {
	s[id/8] |= 1 << (id % 8)
}

// ruleSets holds several ruleSet objects of the same length in a single allocation.
type ruleSets struct {
	// setLen is the number of bytes needed to represent one set
	setLen int
	// bits holds the sets in order. Set i starts at i*setLen.
	bits []uint8
}

// newRuleSets returns n empty sets, each of which can hold ids below idLimit.
func newRuleSets(n, idLimit int) ruleSets {
	setLen := ruleSetLen(idLimit)
	return ruleSets{setLen: setLen, bits: make([]uint8, n*setLen)}
}

// at returns set i.
func (s ruleSets) at(i int) ruleSet {
	return s.bits[i*s.setLen : (i+1)*s.setLen]
}

// all returns an iterator over the ids in s, in ascending order.
func (s ruleSet) all() iter.Seq[int] {
	return func(yield func(int) bool) {
		for i, ids := range s {
			for ids != 0 {
				id := i*8 + bits.TrailingZeros8(ids)
				ids &= ids - 1 // Clear the lowest set bit, which is id's.
				if !yield(id) {
					return
				}
			}
		}
	}
}
