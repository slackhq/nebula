package firewall

import (
	"iter"
	"math/bits"
)

// ruleSet is a set of rule ids, stored as a bitset. s[i] holds ids i*64 through i*64+63, one per bit.
type ruleSet []uint64

// ruleSetLen returns the length of a ruleSet that can hold ids below n.
func ruleSetLen(n int) int {
	return (n + 63) / 64
}

// newRuleSet returns an empty set that can hold ids below idLimit.
func newRuleSet(idLimit int) ruleSet {
	return make(ruleSet, ruleSetLen(idLimit))
}

// add puts id in s.
func (s ruleSet) add(id int) {
	s[id/64] |= 1 << (id % 64)
}

// ruleSets holds several ruleSet objects of the same length in a single allocation.
type ruleSets struct {
	// setLen is the amount of uint64s needed to represent a full set
	setLen int
	// bits holds the sets in order. Set i starts at i*setLen.
	bits []uint64
}

// newRuleSets returns n empty sets, each of which can hold ids below idLimit.
func newRuleSets(n, idLimit int) ruleSets {
	setLen := ruleSetLen(idLimit)
	return ruleSets{setLen: setLen, bits: make([]uint64, n*setLen)}
}

// at returns set i.
func (s ruleSets) at(i int) ruleSet {
	return s.bits[i*s.setLen : (i+1)*s.setLen]
}

// any reports whether pred holds for any id in s. It tries the ids in ascending order and stops at the first
// one for which pred holds.
//
// any walks the set the same way all does, but without a range-over-func iterator, whose state machine costs
// about a nanosecond per call.
func (s ruleSet) any(pred func(id int) bool) bool {
	for i, ids := range s {
		for ids != 0 {
			id := i*64 + bits.TrailingZeros64(ids)
			ids &= ids - 1 // Clear the lowest set bit, which is id's.
			if pred(id) {
				return true
			}
		}
	}
	return false
}

// all returns an iterator over the ids in s, in ascending order.
func (s ruleSet) all() iter.Seq[int] {
	return func(yield func(int) bool) {
		for i, ids := range s {
			for ids != 0 {
				id := i*64 + bits.TrailingZeros64(ids)
				ids &= ids - 1 // Clear the lowest set bit, which is id's.
				if !yield(id) {
					return
				}
			}
		}
	}
}
