package virtqueue

// usedElementSize is the number of bytes needed to store a [UsedElement] in
// memory.
const usedElementSize = 8

// UsedElement is an element of the [UsedRing] and describes a descriptor chain
// that was used by the device.
type UsedElement struct {
	// DescriptorIndex is the index of the head of the used descriptor chain in
	// the [DescriptorTable].
	// The index is 32-bit here for padding reasons.
	DescriptorIndex uint32
	// Length is the number of bytes written into the device writable portion of
	// the buffer described by the descriptor chain.
	Length uint32
}

func (u *UsedElement) GetHead() uint16 {
	return uint16(u.DescriptorIndex)
}
