package virtqueue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckQueueSize(t *testing.T) {
	tests := []struct {
		name        string
		queueSize   int
		containsErr string
	}{
		{
			name:        "negative",
			queueSize:   -1,
			containsErr: "too small",
		},
		{
			name:        "zero",
			queueSize:   0,
			containsErr: "too small",
		},
		{
			name:        "not a power of 2",
			queueSize:   24,
			containsErr: "not a power of 2",
		},
		{
			name:        "too large",
			queueSize:   65536,
			containsErr: "larger than the maximum",
		},
		{
			name:      "valid 1",
			queueSize: 1,
		},
		{
			name:      "valid 256",
			queueSize: 256,
		},

		{
			name:      "valid 32768",
			queueSize: 32768,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckQueueSize(tt.queueSize)
			if tt.containsErr != "" {
				assert.ErrorContains(t, err, tt.containsErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
