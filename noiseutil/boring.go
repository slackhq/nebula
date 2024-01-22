//go:build boringcrypto
// +build boringcrypto

package noiseutil

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	// unsafe needed for go:linkname
	_ "unsafe"

	"github.com/flynn/noise"
)

// EncryptLockNeeded indicates if calls to Encrypt need a lock
// This is true for boringcrypto because the Seal function verifies that the
// nonce is strictly increasing.
const EncryptLockNeeded = true

// NewGCMTLS is no longer exposed in go1.19+, so we need to link it in
// See: https://github.com/golang/go/issues/56326
//
// NewGCMTLS is the internal method used with boringcrypto that provices a
// validated mode of AES-GCM which enforces the nonce is strictly
// monotonically increasing.  This is the TLS 1.2 specification for nonce
// generation (which also matches the method used by the Noise Protocol)
//
// - https://github.com/golang/go/blob/go1.19/src/crypto/tls/cipher_suites.go#L520-L522
// - https://github.com/golang/go/blob/go1.19/src/crypto/internal/boring/aes.go#L235-L237
// - https://github.com/golang/go/blob/go1.19/src/crypto/internal/boring/aes.go#L250
// - https://github.com/google/boringssl/blob/ae223d6138807a13006342edfeef32e813246b39/include/openssl/aead.h#L379-L381
// - https://github.com/google/boringssl/blob/ae223d6138807a13006342edfeef32e813246b39/crypto/fipsmodule/cipher/e_aes.c#L1082-L1093
//
//go:linkname newGCMTLS crypto/internal/boring.NewGCMTLS
func newGCMTLS(c cipher.Block) (cipher.AEAD, error)

type cipherFn struct {
	fn   func([32]byte) noise.Cipher
	name string
}

func (c cipherFn) Cipher(k [32]byte) noise.Cipher { return c.fn(k) }
func (c cipherFn) CipherName() string             { return c.name }

// CipherAESGCM is the AES256-GCM AEAD cipher (using NewGCMTLS when GoBoring is present)
var CipherAESGCM noise.CipherFunc = cipherFn{cipherAESGCMBoring, "AESGCM"}

func cipherAESGCMBoring(k [32]byte) noise.Cipher {
	c, err := aes.NewCipher(k[:])
	if err != nil {
		panic(err)
	}
	gcm, err := newGCMTLS(c)
	if err != nil {
		panic(err)
	}
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
