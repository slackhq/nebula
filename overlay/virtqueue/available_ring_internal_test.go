package virtqueue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAvailableRing_MemoryLayout(t *testing.T) {
	const queueSize = 2

	memory := make([]byte, availableRingSize(queueSize))
	r := newAvailableRing(queueSize, memory)

	*r.flags = 0x01ff
	*r.ringIndex = 1
	r.ring[0] = 0x1234
	r.ring[1] = 0x5678

	assert.Equal(t, []byte{
		0xff, 0x01,
		0x01, 0x00,
		0x34, 0x12,
		0x78, 0x56,
		0x00, 0x00,
	}, memory)
}

func TestAvailableRing_Offer(t *testing.T) {
	const queueSize = 8

	chainHeads := []uint16{42, 33, 69}

	tests := []struct {
		name              string
		startRingIndex    uint16
		expectedRingIndex uint16
		expectedRing      []uint16
	}{
		{
			name:              "no overflow",
			startRingIndex:    0,
			expectedRingIndex: 3,
			expectedRing:      []uint16{42, 33, 69, 0, 0, 0, 0, 0},
		},
		{
			name:              "ring overflow",
			startRingIndex:    6,
			expectedRingIndex: 9,
			expectedRing:      []uint16{69, 0, 0, 0, 0, 0, 42, 33},
		},
		{
			name:              "index overflow",
			startRingIndex:    65535,
			expectedRingIndex: 2,
			expectedRing:      []uint16{33, 69, 0, 0, 0, 0, 0, 42},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			memory := make([]byte, availableRingSize(queueSize))
			r := newAvailableRing(queueSize, memory)
			*r.ringIndex = tt.startRingIndex

			r.offer(chainHeads)

			assert.Equal(t, tt.expectedRingIndex, *r.ringIndex)
			assert.Equal(t, tt.expectedRing, r.ring)
		})
	}
}
