package virtqueue

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitQueue_MemoryAlignment(t *testing.T) {
	tests := []struct {
		name      string
		queueSize int
	}{
		{
			name:      "minimal queue size",
			queueSize: 1,
		},
		{
			name:      "small queue size",
			queueSize: 8,
		},
		{
			name:      "large queue size",
			queueSize: 256,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sq, err := NewSplitQueue(tt.queueSize)
			require.NoError(t, err)

			assert.Zero(t, sq.descriptorTable.Address()%descriptorTableAlignment)
			assert.Zero(t, sq.availableRing.Address()%availableRingAlignment)
			assert.Zero(t, sq.usedRing.Address()%usedRingAlignment)
		})
	}
}

func TestSplitBuffers(t *testing.T) {
	const sizeLimit = 16
	tests := []struct {
		name     string
		buffers  [][]byte
		expected [][]byte
	}{
		{
			name:     "no buffers",
			buffers:  make([][]byte, 0),
			expected: make([][]byte, 0),
		},
		{
			name: "small",
			buffers: [][]byte{
				make([]byte, 11),
			},
			expected: [][]byte{
				make([]byte, 11),
			},
		},
		{
			name: "exact size",
			buffers: [][]byte{
				make([]byte, sizeLimit),
			},
			expected: [][]byte{
				make([]byte, sizeLimit),
			},
		},
		{
			name: "large",
			buffers: [][]byte{
				make([]byte, 42),
			},
			expected: [][]byte{
				make([]byte, 16),
				make([]byte, 16),
				make([]byte, 10),
			},
		},
		{
			name: "mixed",
			buffers: [][]byte{
				make([]byte, 7),
				make([]byte, 30),
				make([]byte, 15),
				make([]byte, 32),
			},
			expected: [][]byte{
				make([]byte, 7),
				make([]byte, 16),
				make([]byte, 14),
				make([]byte, 15),
				make([]byte, 16),
				make([]byte, 16),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := splitBuffers(tt.buffers, sizeLimit)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
