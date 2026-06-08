//go:build !boringcrypto

package noiseutil

import (
	"crypto/fips140"
)

// EncryptLockNeeded indicates if calls to Encrypt need a lock
var EncryptLockNeeded = fips140.Enabled()

// CipherAESGCM is the standard noise.CipherAESGCM when boringcrypto is not enabled
// var CipherAESGCM noise.CipherFunc = noise.CipherAESGCM
