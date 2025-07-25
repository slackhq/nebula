//go:build fips140v1.0
// +build fips140v1.0

package noiseutil

import (
	"crypto/cipher"
	"encoding/binary"

	// unsafe needed for go:linkname
	_ "unsafe"

	"github.com/flynn/noise"
)

// EncryptLockNeeded indicates if calls to Encrypt need a lock
// This is true for fips140 because the Seal function verifies that the
// nonce is strictly increasing.
const EncryptLockNeeded = true

// TODO: Use NewGCMWithCounterNonce once available:
// - https://github.com/golang/go/issues/73110
// Using tls.aeadAESGCM gives us the TLS 1.2 GCM, which also verifies
// that the nonce is strictly increasing.
//
//go:linkname aeadAESGCM crypto/tls.aeadAESGCM
func aeadAESGCM(key, noncePrefix []byte) cipher.AEAD

type cipherFn struct {
	fn   func([32]byte) noise.Cipher
	name string
}

func (c cipherFn) Cipher(k [32]byte) noise.Cipher { return c.fn(k) }
func (c cipherFn) CipherName() string             { return c.name }

// CipherAESGCM is the AES256-GCM AEAD cipher (using aeadAESGCM when fips140 is enabled)
var CipherAESGCM noise.CipherFunc = cipherFn{cipherAESGCM, "AESGCM"}

var emptyPrefix = []byte{0, 0, 0, 0}

func cipherAESGCM(k [32]byte) noise.Cipher {
	// c, err := aes.NewCipher(k[:])
	// if err != nil {
	// 	panic(err)
	// }
	gcm := aeadAESGCM(k[:], emptyPrefix)
	return aeadCipher{
		gcm,
		func(n uint64) []byte {
			var nonce [12]byte
			binary.BigEndian.PutUint64(nonce[4:], n)
			return nonce[:]
		},
	}
}

type aeadCipher struct {
	cipher.AEAD
	nonce func(uint64) []byte
}

func (c aeadCipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	return c.Seal(out, c.nonce(n), plaintext, ad)
}

func (c aeadCipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	return c.Open(out, c.nonce(n), ciphertext, ad)
}
