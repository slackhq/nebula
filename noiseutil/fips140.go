package noiseutil

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"reflect"
	"unsafe"

	// unsafe needed for go:linkname
	_ "crypto/tls"
	_ "unsafe"

	"github.com/flynn/noise"
)

// TODO: Use NewGCMWithCounterNonce or NewGCMForQUIC once available:
// - https://github.com/golang/go/issues/73110
// - https://github.com/golang/go/issues/79219
// Using tls.aeadAESGCMTLS13 gives us the TLS 1.3 GCM, which also verifies
// that the nonce is strictly increasing. This works for both boringcrypto
// and fips140.
//
//go:linkname aeadAESGCMTLS13 crypto/tls.aeadAESGCMTLS13
func aeadAESGCMTLS13(key, noncePrefix []byte) cipher.AEAD

type cipherFn struct {
	fn   func([32]byte) noise.Cipher
	name string
}

func (c cipherFn) Cipher(k [32]byte) noise.Cipher { return c.fn(k) }
func (c cipherFn) CipherName() string             { return c.name }

// CipherAESGCMFIPS140 is the AES256-GCM AEAD cipher (using aeadAESGCM when fips140 is enabled)
var CipherAESGCMFIPS140 noise.CipherFunc = cipherFn{cipherAESGCMFIPS140, "AESGCM"}

// tls.aeadAESGCMTLS13 uses a 4 byte static prefix and an 8 byte XOR mask
var emptyNonce = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func cipherAESGCMFIPS140(k [32]byte) noise.Cipher {
	gcm := aeadAESGCMTLS13(k[:], emptyNonce)
	gcm = extractFIPSAEAD(gcm)
	return &aeadGCMFIPS140Cipher{
		AEAD: gcm,
	}
}

type aeadGCMFIPS140Cipher struct {
	cipher.AEAD
	ready bool
}

// Extract the internal FIPS GCM implementation from the tls wrapper. The TLS
// wrapper is not thread safe around Open, so instead of locking around it we
// can grab the internal implementation that is thread safe. This is the FIPS
// module implementation: `crypto/internal/fips140/aes/gcm.GCMWithXORCounterNonce`
//
// - https://github.com/golang/go/blob/go1.26.4/src/crypto/internal/fips140/aes/gcm/gcm_nonces.go#L212-L287
//
// The wrapper is struct `crypto/tls.xorNonceAEAD` , with field `aead`:
//
// - https://github.com/golang/go/blob/go1.26.4/src/crypto/tls/cipher_suites.go#L482-L487
//
// This can be cleaned up once these FIPS implementations are exposed directly:
//
// - https://github.com/golang/go/issues/73110
func extractFIPSAEAD(xorNonceAEAD cipher.AEAD) cipher.AEAD {
	r := reflect.ValueOf(xorNonceAEAD)
	v := r.Elem().FieldByName("aead")
	v2 := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	return v2.Interface().(cipher.AEAD)
}

func (c *aeadGCMFIPS140Cipher) init(nonce []byte) {
	// GCMWithXORCounterNonce expects that the first call to Seal
	// is with a counter of `0`, this is how it extracts the nonce mask.
	// We can clean this up in the future when NewGCMWithCounterNonce or
	// NewGCMForQUIC are available:
	if !bytes.Equal(emptyNonce, nonce) {
		c.AEAD.Seal([]byte{}, emptyNonce, []byte{}, []byte{})
	}
	c.ready = true
}

func (c *aeadGCMFIPS140Cipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if !c.ready {
		c.init(nonce)
	}
	return c.AEAD.Seal(dst, nonce, plaintext, additionalData)
}

func (c *aeadGCMFIPS140Cipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	return c.Seal(out, aeadGCMFIPS140CipherNonce(n), plaintext, ad)
}

func (c *aeadGCMFIPS140Cipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	return c.Open(out, aeadGCMFIPS140CipherNonce(n), ciphertext, ad)
}

func (c *aeadGCMFIPS140Cipher) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(nb[4:], n)
	out = c.Seal(out, nb, plaintext, ad)
	return out, nil
}

func (c *aeadGCMFIPS140Cipher) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(nb[4:], n)
	return c.Open(out, nb, ciphertext, ad)
}

func aeadGCMFIPS140CipherNonce(n uint64) []byte {
	// GCMWithXORCounterNonce uses a 4 byte static prefix and an 8 byte nonce
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce[:]
}
