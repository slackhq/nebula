package virtqueue

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestDescriptor_Size(t *testing.T) {
	assert.EqualValues(t, descriptorSize, unsafe.Sizeof(Descriptor{}))
}
