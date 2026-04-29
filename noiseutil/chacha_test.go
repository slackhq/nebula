package noiseutil

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCipherChaChaPolyRoundTrip exercises both the noise.Cipher path (allocating)
// and the EncryptDanger/DecryptDanger nb-buffer fast-path on the same cipher.
// They must produce identical ciphertext for the same nonce.
func TestCipherChaChaPolyRoundTrip(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("nebula chachapoly roundtrip")
	ad := []byte("ad")

	c := CipherChaChaPoly.Cipher(key).(*chachaPolyAEAD)

	// noise.Cipher path
	encrypted := c.Encrypt(nil, 42, ad, plaintext)
	decrypted, err := c.Decrypt(nil, 42, ad, encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// nb-buffer path
	nb := make([]byte, 12)
	encrypted2, err := c.EncryptDanger(nil, ad, plaintext, 42, nb)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(encrypted, encrypted2), "Encrypt and EncryptDanger must produce identical ciphertext for the same nonce")

	decrypted2, err := c.DecryptDanger(nil, ad, encrypted2, 42, nb)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)
}
