//go:build !boringcrypto

package noiseutil

import (
	"crypto/fips140"

	"github.com/flynn/noise"
)

// EncryptLockNeeded indicates if calls to Encrypt need a lock
var EncryptLockNeeded = fips140.Enabled()

var CipherAESGCM noise.CipherFunc = initAESGCM()

func initAESGCM() noise.CipherFunc {
	if fips140.Enabled() {
		return CipherAESGCMFIPS140
	} else {
		return noise.CipherAESGCM
	}

}
