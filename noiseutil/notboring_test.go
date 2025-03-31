//go:build !boringcrypto && !fips140
// +build !boringcrypto,!fips140

package noiseutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptLockNeeded(t *testing.T) {
	assert.False(t, EncryptLockNeeded)
}
