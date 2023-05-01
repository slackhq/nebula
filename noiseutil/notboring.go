//go:build !boringcrypto
// +build !boringcrypto

package noiseutil

import (
	"github.com/flynn/noise"
)

// EncryptLockNeeded indicates if calls to Encrypt need a lock
const EncryptLockNeeded = false

// CipherAESGCM is the standard noise.CipherAESGCM when boringcrypto is not enabled
var CipherAESGCM noise.CipherFunc = noise.CipherAESGCM
