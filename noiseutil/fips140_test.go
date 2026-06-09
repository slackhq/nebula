package noiseutil

import (
	"crypto/cipher"
	"crypto/fips140"
	"encoding/hex"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Ensure NewAESGCM validates the nonce is non-repeating
func TestNewAESGCM(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip()
		return
	}

	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	iv, _ := hex.DecodeString("facedbaddecaf888")
	plaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	expected, _ := hex.DecodeString("6a65c2edd45bd63c7e29f40e3d2ed8ba2b99f4c83135383d5676652f255059ceb24863ff10afb1089db701245da87fb88d3acd5f9dd0770cac220c3c04145caf25e190aeb775e7080401c628")

	var keyArray [32]byte
	copy(keyArray[:], key)
	c := CipherAESGCM.Cipher(keyArray)
	aead := c.(cipher.AEAD)

	dst := aead.Seal([]byte{}, iv, plaintext, aad)
	log.Printf("%x", dst)
	assert.Equal(t, expected, dst)

	// We expect this to fail since we are re-encrypting with a repeat IV
	if fips140.Version() == "v1.0.0" {
		assert.PanicsWithValue(t, "crypto/cipher: counter decreased", func() {
			dst = aead.Seal([]byte{}, iv, plaintext, aad)
		})
	} else {
		assert.PanicsWithValue(t, "crypto/cipher: counter decreased or remained the same", func() {
			dst = aead.Seal([]byte{}, iv, plaintext, aad)
		})
	}
}
