//go:build !boringcrypto

package noiseutil

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"

	// unsafe needed for go:linkname
	_ "unsafe"

	"github.com/flynn/noise"
)

// TODO: Use NewGCMWithCounterNonce or NewGCMForQUIC once available:
// - https://github.com/golang/go/issues/73110
// - https://github.com/golang/go/issues/79219
// Using tls.aeadAESGCMTLS13 gives us the TLS 1.3 GCM, which also verifies
// that the nonce is strictly increasing.
//
//go:linkname aeadAESGCMTLS13 crypto/tls.aeadAESGCMTLS13
func aeadAESGCMTLS13(key, noncePrefix []byte) cipher.AEAD

type cipherFn struct {
	fn   func([32]byte) noise.Cipher
	name string
}

func (c cipherFn) Cipher(k [32]byte) noise.Cipher { return c.fn(k) }
func (c cipherFn) CipherName() string             { return c.name }

// CipherAESGCM is the AES256-GCM AEAD cipher (using aeadAESGCM when fips140 is enabled)
var CipherAESGCMFIPS140 noise.CipherFunc = cipherFn{cipherAESGCMFIPS140, "AESGCM"}

// tls.aeadAESGCMTLS13 uses a 4 byte static prefix and an 8 byte XOR mask
var emptyPrefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var emptyNonce = []byte{0, 0, 0, 0, 0, 0, 0, 0}

func cipherAESGCMFIPS140(k [32]byte) noise.Cipher {
	gcm := aeadAESGCMTLS13(k[:], emptyPrefix)
	return &aeadCipher{
		AEAD:  gcm,
		ready: false,
		nonce: func(n uint64) []byte {
			// tls.aeadAESGCMTLS13 uses a 4 byte static prefix and an 8 byte nonce
			var nonce [8]byte
			binary.BigEndian.PutUint64(nonce[:], n)
			return nonce[:]
		},
	}
}

func (c *aeadCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if !c.ready {
		// crypto/tls.aeadAESGCMTLS13 expected that the first call to Seal
		// is with a counter of `0`, this is how it extracts the nonce mask.
		// We can clean this up in the future when NewGCMWithCounterNonce or
		// NewGCMForQUIC are available:
		if !bytes.Equal(emptyNonce, nonce) {
			c.AEAD.Seal([]byte{}, emptyNonce, []byte{}, []byte{})
		}
		c.ready = true
	}
	return c.AEAD.Seal(dst, nonce, plaintext, additionalData)
}

type aeadCipher struct {
	cipher.AEAD
	ready bool
	nonce func(uint64) []byte
}

func (c *aeadCipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	return c.Seal(out, c.nonce(n), plaintext, ad)
}

func (c *aeadCipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	return c.Open(out, c.nonce(n), ciphertext, ad)
}

func (c *aeadCipher) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(nb[4:], n)
	out = c.Seal(out, nb[4:], plaintext, ad)
	return out, nil
}

func (c *aeadCipher) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(nb[4:], n)
	return c.Open(out, nb[4:], ciphertext, ad)
}
