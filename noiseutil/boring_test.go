//go:build boringcrypto
// +build boringcrypto

package noiseutil

import (
	"crypto/boring"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptLockNeeded(t *testing.T) {
	assert.True(t, EncryptLockNeeded)
}

// Ensure NewGCMTLS validates the nonce is non-repeating
func TestNewGCMTLS(t *testing.T) {
	assert.True(t, boring.Enabled())

	// Test Case 16 from GCM Spec:
	//  - (now dead link): http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
	//  - as listed in boringssl tests: https://github.com/google/boringssl/blob/fips-20220613/crypto/cipher_extra/test/cipher_tests.txt#L412-L418
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	iv, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	plaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	expected, _ := hex.DecodeString("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
	expectedTag, _ := hex.DecodeString("76fc6ece0f4e1768cddf8853bb2d551b")

	expected = append(expected, expectedTag...)

	var keyArray [32]byte
	copy(keyArray[:], key)
	c := CipherAESGCM.Cipher(keyArray)
	aead := c.(aeadCipher).AEAD

	dst := aead.Seal([]byte{}, iv, plaintext, aad)
	assert.Equal(t, expected, dst)

	// We expect this to fail since we are re-encrypting with a repeat IV
	assert.PanicsWithError(t, "boringcrypto: EVP_AEAD_CTX_seal failed", func() {
		dst = aead.Seal([]byte{}, iv, plaintext, aad)
	})
}
