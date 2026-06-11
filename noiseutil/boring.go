//go:build boringcrypto
// +build boringcrypto

package noiseutil

import (
	"crypto/boring"

	"github.com/flynn/noise"
)

var CipherAESGCM noise.CipherFunc = CipherAESGCMFIPS140

// EncryptLockNeeded indicates if calls to Encrypt need a lock
// This is true for boringcrypto because the Seal function verifies that the
// nonce is strictly increasing.
const EncryptLockNeeded = true

var boringEnabled = boring.Enabled()
