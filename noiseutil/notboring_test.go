//go:build !boringcrypto && !fips140v1.0
// +build !boringcrypto,!fips140v1.0

package noiseutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptLockNeeded(t *testing.T) {
	assert.False(t, EncryptLockNeeded)
}
