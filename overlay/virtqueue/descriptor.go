package virtqueue

// descriptorFlag is a flag that describes a [Descriptor].
type descriptorFlag uint16

const (
	// descriptorFlagHasNext marks a descriptor chain as continuing via the next
	// field.
	descriptorFlagHasNext descriptorFlag = 1 << iota
	// descriptorFlagWritable marks a buffer as device write-only (otherwise
	// device read-only).
	descriptorFlagWritable
	// descriptorFlagIndirect means the buffer contains a list of buffer
	// descriptors to provide an additional layer of indirection.
	// Only allowed when the [virtio.FeatureIndirectDescriptors] feature was
	// negotiated.
	descriptorFlagIndirect
)

// descriptorSize is the number of bytes needed to store a [Descriptor] in
// memory.
const descriptorSize = 16

// Descriptor describes (a part of) a buffer which is either read-only for the
// device or write-only for the device (depending on [descriptorFlagWritable]).
// Multiple descriptors can be chained to produce a "descriptor chain" that can
// contain both device-readable and device-writable buffers. Device-readable
// descriptors always come first in a chain. A single, large buffer may be
// split up by chaining multiple similar descriptors that reference different
// memory pages. This is required, because buffers may exceed a single page size
// and the memory accessed by the device is expected to be continuous.
type Descriptor struct {
	// address is the address to the continuous memory holding the data for this
	// descriptor.
	address uintptr
	// length is the amount of bytes stored at address.
	length uint32
	// flags that describe this descriptor.
	flags descriptorFlag
	// next contains the index of the next descriptor continuing this descriptor
	// chain when the [descriptorFlagHasNext] flag is set.
	next uint16
}
