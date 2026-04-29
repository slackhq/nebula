package noiseutil

import (
	"github.com/flynn/noise"
)

// Cipher is the AEAD interface ConnectionState holds for both flynn/noise's
// handshake and Nebula's data plane. EncryptDanger/DecryptDanger take a
// caller-provided 12-byte nonce buffer so the per-packet path doesn't heap
// allocate. Encrypt/Decrypt satisfy noise.Cipher for the handshake. Each
// concrete cipher (strict/std/chacha/boring) handles its own endianness and
// nonce layout inline.
type Cipher interface {
	noise.Cipher
	EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error)
	DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error)
	Overhead() int
}

// cipherFn pairs a per-cipher constructor with its name to satisfy
// noise.CipherFunc.
type cipherFn struct {
	fn   func([32]byte) noise.Cipher
	name string
}

func (c cipherFn) Cipher(k [32]byte) noise.Cipher { return c.fn(k) }
func (c cipherFn) CipherName() string             { return c.name }
