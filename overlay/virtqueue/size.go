package virtqueue

import (
	"errors"
	"fmt"
)

// ErrQueueSizeInvalid is returned when a queue size is invalid.
var ErrQueueSizeInvalid = errors.New("queue size is invalid")

// CheckQueueSize checks if the given value would be a valid size for a
// virtqueue and returns an [ErrQueueSizeInvalid], if not.
func CheckQueueSize(queueSize int) error {
	if queueSize <= 0 {
		return fmt.Errorf("%w: %d is too small", ErrQueueSizeInvalid, queueSize)
	}

	// The queue size must always be a power of 2.
	// This ensures that ring indexes wrap correctly when the 16-bit integers
	// overflow.
	if queueSize&(queueSize-1) != 0 {
		return fmt.Errorf("%w: %d is not a power of 2", ErrQueueSizeInvalid, queueSize)
	}

	// The largest power of 2 that fits into a 16-bit integer is 32768.
	// 2 * 32768 would be 65536 which no longer fits.
	if queueSize > 32768 {
		return fmt.Errorf("%w: %d is larger than the maximum possible queue size 32768",
			ErrQueueSizeInvalid, queueSize)
	}

	return nil
}
