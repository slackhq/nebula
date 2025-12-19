package virtqueue

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestUsedElement_Size(t *testing.T) {
	assert.EqualValues(t, usedElementSize, unsafe.Sizeof(UsedElement{}))
}
