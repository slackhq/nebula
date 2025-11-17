package virtqueue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsedRing_MemoryLayout(t *testing.T) {
	const queueSize = 2

	memory := make([]byte, usedRingSize(queueSize))
	r := newUsedRing(queueSize, memory)

	*r.flags = 0x01ff
	*r.ringIndex = 1
	r.ring[0] = UsedElement{
		DescriptorIndex: 0x0123,
		Length:          0x4567,
	}
	r.ring[1] = UsedElement{
		DescriptorIndex: 0x89ab,
		Length:          0xcdef,
	}

	assert.Equal(t, []byte{
		0xff, 0x01,
		0x01, 0x00,
		0x23, 0x01, 0x00, 0x00,
		0x67, 0x45, 0x00, 0x00,
		0xab, 0x89, 0x00, 0x00,
		0xef, 0xcd, 0x00, 0x00,
		0x00, 0x00,
	}, memory)
}

//func TestUsedRing_Take(t *testing.T) {
//	const queueSize = 8
//
//	tests := []struct {
//		name      string
//		ring      []UsedElement
//		ringIndex uint16
//		lastIndex uint16
//		expected  []UsedElement
//	}{
//		{
//			name: "nothing new",
//			ring: []UsedElement{
//				{DescriptorIndex: 1},
//				{DescriptorIndex: 2},
//				{DescriptorIndex: 3},
//				{DescriptorIndex: 4},
//				{},
//				{},
//				{},
//				{},
//			},
//			ringIndex: 4,
//			lastIndex: 4,
//			expected:  nil,
//		},
//		{
//			name: "no overflow",
//			ring: []UsedElement{
//				{DescriptorIndex: 1},
//				{DescriptorIndex: 2},
//				{DescriptorIndex: 3},
//				{DescriptorIndex: 4},
//				{},
//				{},
//				{},
//				{},
//			},
//			ringIndex: 4,
//			lastIndex: 1,
//			expected: []UsedElement{
//				{DescriptorIndex: 2},
//				{DescriptorIndex: 3},
//				{DescriptorIndex: 4},
//			},
//		},
//		{
//			name: "ring overflow",
//			ring: []UsedElement{
//				{DescriptorIndex: 9},
//				{DescriptorIndex: 10},
//				{DescriptorIndex: 3},
//				{DescriptorIndex: 4},
//				{DescriptorIndex: 5},
//				{DescriptorIndex: 6},
//				{DescriptorIndex: 7},
//				{DescriptorIndex: 8},
//			},
//			ringIndex: 10,
//			lastIndex: 7,
//			expected: []UsedElement{
//				{DescriptorIndex: 8},
//				{DescriptorIndex: 9},
//				{DescriptorIndex: 10},
//			},
//		},
//		{
//			name: "index overflow",
//			ring: []UsedElement{
//				{DescriptorIndex: 9},
//				{DescriptorIndex: 10},
//				{DescriptorIndex: 3},
//				{DescriptorIndex: 4},
//				{DescriptorIndex: 5},
//				{DescriptorIndex: 6},
//				{DescriptorIndex: 7},
//				{DescriptorIndex: 8},
//			},
//			ringIndex: 2,
//			lastIndex: 65535,
//			expected: []UsedElement{
//				{DescriptorIndex: 8},
//				{DescriptorIndex: 9},
//				{DescriptorIndex: 10},
//			},
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			memory := make([]byte, usedRingSize(queueSize))
//			r := newUsedRing(queueSize, memory)
//
//			copy(r.ring, tt.ring)
//			*r.ringIndex = tt.ringIndex
//			r.lastIndex = tt.lastIndex
//
//			assert.Equal(t, tt.expected, r.take())
//		})
//	}
//}
