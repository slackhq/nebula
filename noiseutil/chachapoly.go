package noiseutil

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/flynn/noise"
)

// CipherStateChaChaPoly is the data-plane wrapper for the ChaCha20-Poly1305 AEAD cipher.
// ChaCha20-Poly1305 uses little-endian nonce encoding per the Noise spec.
type CipherStateChaChaPoly struct {
	c cipher.AEAD
}

// NewCipherStateChaChaPoly extracts the underlying AEAD from the post-handshake noise.CipherState.
// The caller is responsible for ensuring the noise cipher is actually ChaCha20-Poly1305.
func NewCipherStateChaChaPoly(s *noise.CipherState) *CipherStateChaChaPoly {
	return &CipherStateChaChaPoly{c: s.Cipher().(cipher.AEAD)}
}

func (s *CipherStateChaChaPoly) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("no cipher state available to encrypt")
	}
	nb[0] = 0
	nb[1] = 0
	nb[2] = 0
	nb[3] = 0
	binary.LittleEndian.PutUint64(nb[4:], n)
	return s.c.Seal(out, nb, plaintext, ad), nil
}

func (s *CipherStateChaChaPoly) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	if s == nil {
		return []byte{}, nil
	}
	nb[0] = 0
	nb[1] = 0
	nb[2] = 0
	nb[3] = 0
	binary.LittleEndian.PutUint64(nb[4:], n)
	return s.c.Open(out, nb, ciphertext, ad)
}

func (s *CipherStateChaChaPoly) Overhead() int {
	if s == nil {
		return 0
	}
	return s.c.Overhead()
}
