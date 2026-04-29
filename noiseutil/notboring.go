//go:build !boringcrypto
// +build !boringcrypto

package noiseutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"encoding/binary"

	// unsafe needed for go:linkname
	_ "unsafe"

	"github.com/flynn/noise"
)

// EncryptLockNeeded indicates whether callers must serialize the
// counter-increment + Seal pair. The strict-nonce AES-GCM used when FIPS 140-3
// mode is on at runtime panics on nonce reuse, so we serialize. With FIPS off
// the standard AES-GCM has no such constraint, so we skip the lock. The value
// is computed at package init from crypto/fips140.Enabled() and cannot change
// afterwards (Go fixes the fips140 GODEBUG at process start).
var EncryptLockNeeded = fips140.Enabled()

// We use crypto/tls.aeadAESGCM for the FIPS 140-3 strict-nonce GCM. It panics
// on nonce reuse, which is a defense-in-depth check on top of our own atomic
// counter.
//
// TODO: Replace with crypto/cipher.NewGCMWithCounterNonce once it exists:
//   - https://github.com/golang/go/issues/73110
//
//go:linkname aeadAESGCM crypto/tls.aeadAESGCM
func aeadAESGCM(key, noncePrefix []byte) cipher.AEAD

// CipherAESGCM picks the underlying AES-GCM at construction based on
// fips140.Enabled(): the FIPS-validated strict-nonce GCM when on, the standard
// GCM otherwise.
var CipherAESGCM noise.CipherFunc = cipherFn{cipherAESGCM, "AESGCM"}

// tls.aeadAESGCM bakes a 4-byte static prefix into the cipher; Seal/Open then
// take only the 8-byte counter portion of the nonce.
var emptyPrefix = []byte{0, 0, 0, 0}

func cipherAESGCM(k [32]byte) noise.Cipher {
	if fips140.Enabled() {
		return &strictAEAD{
			aeadAESGCM(k[:], emptyPrefix),
			func(n uint64) []byte {
				var nonce [8]byte
				binary.BigEndian.PutUint64(nonce[:], n)
				return nonce[:]
			},
		}
	}
	c, err := aes.NewCipher(k[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}
	return &stdAEAD{gcm}
}

// strictAEAD wraps tls.aeadAESGCM (the FIPS-validated, strict-nonce GCM).
// Seal/Open take an 8-byte counter; the 4-byte static prefix is baked in.
// All paths go through the c.nonce closure (matching the boringcrypto pattern)
// because the strict-nonce AEAD panics if the same counter is reused, so we
// don't want to risk a stale caller buffer here.
type strictAEAD struct {
	cipher.AEAD
	nonce func(uint64) []byte
}

func (c *strictAEAD) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	return c.Seal(out, c.nonce(n), plaintext, ad)
}

func (c *strictAEAD) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	return c.Open(out, c.nonce(n), ciphertext, ad)
}

func (c *strictAEAD) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	return c.Seal(out, c.nonce(n), plaintext, ad), nil
}

func (c *strictAEAD) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	return c.Open(out, c.nonce(n), ciphertext, ad)
}

// stdAEAD wraps cipher.NewGCM (the standard, non-FIPS-strict GCM).
// Seal/Open take a 12-byte nonce composed of a 4-byte zero prefix and the
// 8-byte counter.
type stdAEAD struct {
	cipher.AEAD
}

func (c *stdAEAD) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], n)
	return c.Seal(out, nonce[:], plaintext, ad)
}

func (c *stdAEAD) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], n)
	return c.Open(out, nonce[:], ciphertext, ad)
}

func (c *stdAEAD) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	nb[0] = 0
	nb[1] = 0
	nb[2] = 0
	nb[3] = 0
	binary.BigEndian.PutUint64(nb[4:], n)
	return c.Seal(out, nb, plaintext, ad), nil
}

func (c *stdAEAD) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	nb[0] = 0
	nb[1] = 0
	nb[2] = 0
	nb[3] = 0
	binary.BigEndian.PutUint64(nb[4:], n)
	return c.Open(out, nb, ciphertext, ad)
}
