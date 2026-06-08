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
	expected, _ := hex.DecodeString("72ce2ea385f88c20d856e9d1248c2ca08562bbe8a61459ffae06ec393540518e9b6b4c40a146053f26a3df83c5384a48d273148b15aba64d970107432b2892741359275676441c1572c3fa9e")

	var keyArray [32]byte
	copy(keyArray[:], key)
	c := CipherAESGCM.Cipher(keyArray)
	aead := c.(cipher.AEAD)

	dst := aead.Seal([]byte{}, iv, plaintext, aad)
	log.Printf("%x", dst)
	assert.Equal(t, expected, dst)

	// We expect this to fail since we are re-encrypting with a repeat IV
	assert.PanicsWithValue(t, "crypto/cipher: counter decreased or remained the same", func() {
		dst = aead.Seal([]byte{}, iv, plaintext, aad)
	})
}
