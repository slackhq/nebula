package noiseutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"

	// unsafe needed for go:linkname
	_ "crypto/tls"
	_ "unsafe"

	"github.com/flynn/noise"
)

type cipherFn struct {
	fn   func([32]byte) noise.Cipher
	name string
}

func (c cipherFn) Cipher(k [32]byte) noise.Cipher { return c.fn(k) }
func (c cipherFn) CipherName() string             { return c.name }

// CipherAESGCMFIPS140 is the AES256-GCM AEAD cipher (using tls.aeadAESGCMTLS13, for both boringcrypto and fips140)
var CipherAESGCMFIPS140 noise.CipherFunc = cipherFn{cipherAESGCMFIPS140, "AESGCM"}

// tls.aeadAESGCMTLS13 uses a 4 byte static prefix and an 8 byte XOR mask
var emptyNonce = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func cipherAESGCMFIPS140(k [32]byte) noise.Cipher {
	c, err := aes.NewCipher(k[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCMWithCounterNonce(c)
	if err != nil {
		panic(err)
	}
	return &aeadGCMFIPS140Cipher{
		AEAD: gcm,
	}
}

type aeadGCMFIPS140Cipher struct {
	cipher.AEAD
}

func (c *aeadGCMFIPS140Cipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	return c.Seal(out, aeadGCMFIPS140CipherNonce(n), plaintext, ad)
}

func (c *aeadGCMFIPS140Cipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	return c.Open(out, aeadGCMFIPS140CipherNonce(n), ciphertext, ad)
}

func (c *aeadGCMFIPS140Cipher) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	if c == nil {
		return nil, errors.New("no cipher state available to encrypt")
	}
	if n >= RejectAfterMessages {
		return nil, ErrMessageCounterExhausted
	}
	binary.BigEndian.PutUint64(nb[4:], n)
	out = c.Seal(out, nb, plaintext, ad)
	return out, nil
}

func (c *aeadGCMFIPS140Cipher) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	if c == nil {
		return []byte{}, nil
	}
	binary.BigEndian.PutUint64(nb[4:], n)
	return c.Open(out, nb, ciphertext, ad)
}

func aeadGCMFIPS140CipherNonce(n uint64) []byte {
	// GCMWithCounterNonce uses a 4 byte static prefix and an 8 byte nonce
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce[:]
}

func init() {
	if boringEnabled || fips140.Enabled() {
		initSelfTestAESGCMFIPS140()
	}
}

// validates the go:linkname + reflection extraction and the nonce-reuse
// protection at startup. cipherAESGCMFIPS140 relies on unexported
// crypto/tls and crypto/internal/fips140 internals; if a future Go version changes
// those, this fails fast with a clear message instead of panicking per-handshake
// (or, worse, silently losing the strictly-increasing nonce check that is the whole
// point of using this cipher).
func initSelfTestAESGCMFIPS140() {
	var key [32]byte
	c := cipherAESGCMFIPS140(key)

	// Verify the extracted AEAD produces a working encrypt/decrypt roundtrip.
	plaintext := []byte("nebula fips140 self-test")
	ad := []byte("ad")
	ct := c.Encrypt(nil, 1, ad, plaintext)
	pt, err := c.Decrypt(nil, 1, ad, ct)
	if err != nil {
		panic(fmt.Sprintf("noiseutil: FIPS AES-GCM self-test roundtrip failed on %s: %v", runtime.Version(), err))
	}
	if !bytes.Equal(pt, plaintext) {
		panic(fmt.Sprintf("noiseutil: FIPS AES-GCM self-test roundtrip returned wrong plaintext on %s", runtime.Version()))
	}

	// Verify the nonce-reuse protection still fires: re-encrypting with the same
	// counter must panic. This is the defensive check that FIPS-140 requires, so
	// if the extraction ever silently yields an AEAD without it, refuse to start.
	if !reusePanics(c) {
		panic(fmt.Sprintf("noiseutil: FIPS AES-GCM self-test did not reject a reused nonce on %s; nonce-reuse protection is missing (incompatible Go version)", runtime.Version()))
	}
}

// reusePanics reports whether re-encrypting with an already-used counter panics,
// as GCMWithXORCounterNonce is expected to.
func reusePanics(c noise.Cipher) (panicked bool) {
	c.Encrypt(nil, 2, nil, nil)
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	c.Encrypt(nil, 2, nil, nil)
	return false
}
