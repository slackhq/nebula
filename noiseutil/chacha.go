package noiseutil

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
)

// CipherChaChaPoly is ChaCha20-Poly1305 in the Noise nonce convention: 12-byte
// nonce = 4-byte zero prefix + 8-byte little-endian counter. Endianness is
// inline here, not on a global, so AES and ChaCha can coexist in the same
// process without stepping on each other.
var CipherChaChaPoly noise.CipherFunc = cipherFn{cipherChaChaPoly, "ChaChaPoly"}

func cipherChaChaPoly(k [32]byte) noise.Cipher {
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		panic(err)
	}
	return &chachaPolyAEAD{aead}
}

type chachaPolyAEAD struct {
	cipher.AEAD
}

func (c *chachaPolyAEAD) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return c.Seal(out, nonce[:], plaintext, ad)
}

func (c *chachaPolyAEAD) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return c.Open(out, nonce[:], ciphertext, ad)
}

func (c *chachaPolyAEAD) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	nb[0] = 0
	nb[1] = 0
	nb[2] = 0
	nb[3] = 0
	binary.LittleEndian.PutUint64(nb[4:], n)
	return c.Seal(out, nb, plaintext, ad), nil
}

func (c *chachaPolyAEAD) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	nb[0] = 0
	nb[1] = 0
	nb[2] = 0
	nb[3] = 0
	binary.LittleEndian.PutUint64(nb[4:], n)
	return c.Open(out, nb, ciphertext, ad)
}
