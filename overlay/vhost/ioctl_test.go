package vhost_test

import (
	"testing"
	"unsafe"

	"github.com/slackhq/nebula/overlay/vhost"
	"github.com/stretchr/testify/assert"
)

func TestQueueState_Size(t *testing.T) {
	assert.EqualValues(t, 8, unsafe.Sizeof(vhost.QueueState{}))
}

func TestQueueAddresses_Size(t *testing.T) {
	assert.EqualValues(t, 40, unsafe.Sizeof(vhost.QueueAddresses{}))
}

func TestQueueFile_Size(t *testing.T) {
	assert.EqualValues(t, 8, unsafe.Sizeof(vhost.QueueFile{}))
}
