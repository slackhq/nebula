//go:build !boringcrypto
// +build !boringcrypto

package noiseutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptLockNeeded(t *testing.T) {
	assert.False(t, EncryptLockNeeded)
}
