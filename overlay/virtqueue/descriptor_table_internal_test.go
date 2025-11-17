package virtqueue

import (
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestDescriptorTable_InitializeDescriptors(t *testing.T) {
	const queueSize = 32

	dt := DescriptorTable{
		descriptors: make([]Descriptor, queueSize),
	}

	assert.NoError(t, dt.initializeDescriptors())
	t.Cleanup(func() {
		assert.NoError(t, dt.releaseBuffers())
	})

	for i, descriptor := range dt.descriptors {
		assert.NotZero(t, descriptor.address)
		assert.Zero(t, descriptor.length)
		assert.EqualValues(t, descriptorFlagHasNext, descriptor.flags)
		assert.EqualValues(t, (i+1)%queueSize, descriptor.next)
	}
}

func TestDescriptorTable_DescriptorChains(t *testing.T) {
	// Use a very short queue size to not make this test overly verbose.
	const queueSize = 8

	pageSize := os.Getpagesize() * 2

	// Initialize descriptor table.
	dt := DescriptorTable{
		descriptors: make([]Descriptor, queueSize),
	}
	assert.NoError(t, dt.initializeDescriptors())
	t.Cleanup(func() {
		assert.NoError(t, dt.releaseBuffers())
	})

	// Some utilities for easier checking if the descriptor table looks as
	// expected.
	type desc struct {
		buffer []byte
		flags  descriptorFlag
		next   uint16
	}
	assertDescriptorTable := func(expected [queueSize]desc) {
		for i := 0; i < queueSize; i++ {
			actualDesc := &dt.descriptors[i]
			expectedDesc := &expected[i]
			assert.Equal(t, uint32(len(expectedDesc.buffer)), actualDesc.length)
			if len(expectedDesc.buffer) > 0 {
				//goland:noinspection GoVetUnsafePointer
				assert.EqualValues(t,
					unsafe.Slice((*byte)(unsafe.Pointer(actualDesc.address)), actualDesc.length),
					expectedDesc.buffer)
			}
			assert.Equal(t, expectedDesc.flags, actualDesc.flags)
			if expectedDesc.flags&descriptorFlagHasNext != 0 {
				assert.Equal(t, expectedDesc.next, actualDesc.next)
			}
		}
	}

	// Initial state: All descriptors are in the free chain.
	assert.Equal(t, uint16(0), dt.freeHeadIndex)
	assert.Equal(t, uint16(8), dt.freeNum)
	assertDescriptorTable([queueSize]desc{
		{
			// Free head.
			flags: descriptorFlagHasNext,
			next:  1,
		},
		{
			flags: descriptorFlagHasNext,
			next:  2,
		},
		{
			flags: descriptorFlagHasNext,
			next:  3,
		},
		{
			flags: descriptorFlagHasNext,
			next:  4,
		},
		{
			flags: descriptorFlagHasNext,
			next:  5,
		},
		{
			flags: descriptorFlagHasNext,
			next:  6,
		},
		{
			flags: descriptorFlagHasNext,
			next:  7,
		},
		{
			flags: descriptorFlagHasNext,
			next:  0,
		},
	})

	// Create the first chain.
	firstChain, err := dt.createDescriptorChain([][]byte{
		makeTestBuffer(t, 26),
		makeTestBuffer(t, 256),
	}, 1)
	assert.NoError(t, err)
	assert.Equal(t, uint16(1), firstChain)

	// Now there should be a new chain next to the free chain.
	assert.Equal(t, uint16(0), dt.freeHeadIndex)
	assert.Equal(t, uint16(5), dt.freeNum)
	assertDescriptorTable([queueSize]desc{
		{
			// Free head.
			flags: descriptorFlagHasNext,
			next:  4,
		},
		{
			// Head of first chain.
			buffer: makeTestBuffer(t, 26),
			flags:  descriptorFlagHasNext,
			next:   2,
		},
		{
			buffer: makeTestBuffer(t, 256),
			flags:  descriptorFlagHasNext,
			next:   3,
		},
		{
			// Tail of first chain.
			buffer: make([]byte, pageSize),
			flags:  descriptorFlagWritable,
		},
		{
			flags: descriptorFlagHasNext,
			next:  5,
		},
		{
			flags: descriptorFlagHasNext,
			next:  6,
		},
		{
			flags: descriptorFlagHasNext,
			next:  7,
		},
		{
			flags: descriptorFlagHasNext,
			next:  0,
		},
	})

	// Create a second chain with only a single in buffer.
	secondChain, err := dt.createDescriptorChain(nil, 1)
	assert.NoError(t, err)
	assert.Equal(t, uint16(4), secondChain)

	// Now there should be two chains next to the free chain.
	assert.Equal(t, uint16(0), dt.freeHeadIndex)
	assert.Equal(t, uint16(4), dt.freeNum)
	assertDescriptorTable([queueSize]desc{
		{
			// Free head.
			flags: descriptorFlagHasNext,
			next:  5,
		},
		{
			// Head of the first chain.
			buffer: makeTestBuffer(t, 26),
			flags:  descriptorFlagHasNext,
			next:   2,
		},
		{
			buffer: makeTestBuffer(t, 256),
			flags:  descriptorFlagHasNext,
			next:   3,
		},
		{
			// Tail of the first chain.
			buffer: make([]byte, pageSize),
			flags:  descriptorFlagWritable,
		},
		{
			// Head and tail of the second chain.
			buffer: make([]byte, pageSize),
			flags:  descriptorFlagWritable,
		},
		{
			flags: descriptorFlagHasNext,
			next:  6,
		},
		{
			flags: descriptorFlagHasNext,
			next:  7,
		},
		{
			flags: descriptorFlagHasNext,
			next:  0,
		},
	})

	// Create a third chain taking up all remaining descriptors.
	thirdChain, err := dt.createDescriptorChain([][]byte{
		makeTestBuffer(t, 42),
		makeTestBuffer(t, 96),
		makeTestBuffer(t, 33),
		makeTestBuffer(t, 222),
	}, 0)
	assert.NoError(t, err)
	assert.Equal(t, uint16(5), thirdChain)

	// Now there should be three chains and no free chain.
	assert.Equal(t, noFreeHead, dt.freeHeadIndex)
	assert.Equal(t, uint16(0), dt.freeNum)
	assertDescriptorTable([queueSize]desc{
		{
			// Tail of the third chain.
			buffer: makeTestBuffer(t, 222),
		},
		{
			// Head of the first chain.
			buffer: makeTestBuffer(t, 26),
			flags:  descriptorFlagHasNext,
			next:   2,
		},
		{
			buffer: makeTestBuffer(t, 256),
			flags:  descriptorFlagHasNext,
			next:   3,
		},
		{
			// Tail of the first chain.
			buffer: make([]byte, pageSize),
			flags:  descriptorFlagWritable,
		},
		{
			// Head and tail of the second chain.
			buffer: make([]byte, pageSize),
			flags:  descriptorFlagWritable,
		},
		{
			// Head of the third chain.
			buffer: makeTestBuffer(t, 42),
			flags:  descriptorFlagHasNext,
			next:   6,
		},
		{
			buffer: makeTestBuffer(t, 96),
			flags:  descriptorFlagHasNext,
			next:   7,
		},
		{
			buffer: makeTestBuffer(t, 33),
			flags:  descriptorFlagHasNext,
			next:   0,
		},
	})

	// Free the third chain.
	assert.NoError(t, dt.freeDescriptorChain(thirdChain))

	// Now there should be two chains and a free chain again.
	assert.Equal(t, uint16(5), dt.freeHeadIndex)
	assert.Equal(t, uint16(4), dt.freeNum)
	assertDescriptorTable([queueSize]desc{
		{
			flags: descriptorFlagHasNext,
			next:  5,
		},
		{
			// Head of the first chain.
			buffer: makeTestBuffer(t, 26),
			flags:  descriptorFlagHasNext,
			next:   2,
		},
		{
			buffer: makeTestBuffer(t, 256),
			flags:  descriptorFlagHasNext,
			next:   3,
		},
		{
			// Tail of the first chain.
			buffer: make([]byte, pageSize),
			flags:  descriptorFlagWritable,
		},
		{
			// Head and tail of the second chain.
			buffer: make([]byte, pageSize),
			flags:  descriptorFlagWritable,
		},
		{
			// Free head.
			flags: descriptorFlagHasNext,
			next:  6,
		},
		{
			flags: descriptorFlagHasNext,
			next:  7,
		},
		{
			flags: descriptorFlagHasNext,
			next:  0,
		},
	})

	// Free the first chain.
	assert.NoError(t, dt.freeDescriptorChain(firstChain))

	// Now there should be only a single chain next to the free chain.
	assert.Equal(t, uint16(5), dt.freeHeadIndex)
	assert.Equal(t, uint16(7), dt.freeNum)
	assertDescriptorTable([queueSize]desc{
		{
			flags: descriptorFlagHasNext,
			next:  5,
		},
		{
			flags: descriptorFlagHasNext,
			next:  2,
		},
		{
			flags: descriptorFlagHasNext,
			next:  3,
		},
		{
			flags: descriptorFlagHasNext,
			next:  6,
		},
		{
			// Head and tail of the second chain.
			buffer: make([]byte, pageSize),
			flags:  descriptorFlagWritable,
		},
		{
			// Free head.
			flags: descriptorFlagHasNext,
			next:  1,
		},
		{
			flags: descriptorFlagHasNext,
			next:  7,
		},
		{
			flags: descriptorFlagHasNext,
			next:  0,
		},
	})

	// Free the second chain.
	assert.NoError(t, dt.freeDescriptorChain(secondChain))

	// Now all descriptors should be in the free chain again.
	assert.Equal(t, uint16(5), dt.freeHeadIndex)
	assert.Equal(t, uint16(8), dt.freeNum)
	assertDescriptorTable([queueSize]desc{
		{
			flags: descriptorFlagHasNext,
			next:  5,
		},
		{
			flags: descriptorFlagHasNext,
			next:  2,
		},
		{
			flags: descriptorFlagHasNext,
			next:  3,
		},
		{
			flags: descriptorFlagHasNext,
			next:  6,
		},
		{
			flags: descriptorFlagHasNext,
			next:  1,
		},
		{
			// Free head.
			flags: descriptorFlagHasNext,
			next:  4,
		},
		{
			flags: descriptorFlagHasNext,
			next:  7,
		},
		{
			flags: descriptorFlagHasNext,
			next:  0,
		},
	})
}

func makeTestBuffer(t *testing.T, length int) []byte {
	t.Helper()
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = byte(length - i)
	}
	return buf
}
