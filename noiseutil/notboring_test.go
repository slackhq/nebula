//go:build !boringcrypto
// +build !boringcrypto

package noiseutil

import (
	"crypto/fips140"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptLockNeeded(t *testing.T) {
	// EncryptLockNeeded mirrors the runtime fips140 state set via
	// crypto/fips140.Enabled() (which itself is fixed at process start
	// from GOFIPS140 / GODEBUG=fips140).
	assert.Equal(t, fips140.Enabled(), EncryptLockNeeded)
}

// TestStrictAEADRejectsNonceReuse confirms that when fips140 is on at runtime
// we end up using the strict-nonce AES-GCM (tls.aeadAESGCM), which panics if
// the same counter is used twice. With fips140 off the standard GCM does not
// enforce this, so we skip.
func TestStrictAEADRejectsNonceReuse(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("strict-nonce AES-GCM only used when fips140.Enabled() is true")
	}

	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	iv, _ := hex.DecodeString("00000000facedbaddecaf888")
	plaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	expected, _ := hex.DecodeString("72ce2ea385f88c20d856e9d1248c2ca08562bbe8a61459ffae06ec393540518e9b6b4c40a146053f26a3df83c5384a48d273148b15aba64d970107432b2892741359275676441c1572c3fa9e")

	var keyArray [32]byte
	copy(keyArray[:], key)
	aead := CipherAESGCM.Cipher(keyArray).(*strictAEAD).AEAD

	dst := aead.Seal([]byte{}, iv, plaintext, aad)
	assert.Equal(t, expected, dst)

	// Re-encrypting with the same iv must panic.
	assert.PanicsWithValue(t, "crypto/cipher: counter decreased", func() {
		_ = aead.Seal([]byte{}, iv, plaintext, aad)
	})
}
