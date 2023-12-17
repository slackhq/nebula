package cert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// KDF factors
type Argon2Parameters struct {
	version     rune
	Memory      uint32 // KiB
	Parallelism uint8
	Iterations  uint32
	salt        []byte
}

// Returns a new Argon2Parameters object with current version set
func NewArgon2Parameters(memory uint32, parallelism uint8, iterations uint32) *Argon2Parameters {
	return &Argon2Parameters{
		version:     argon2.Version,
		Memory:      memory, // KiB
		Parallelism: parallelism,
		Iterations:  iterations,
	}
}

// Encrypts data using AES-256-GCM and the Argon2id key derivation function
func aes256Encrypt(passphrase []byte, kdfParams *Argon2Parameters, data []byte) ([]byte, error) {
	key, err := aes256DeriveKey(passphrase, kdfParams)
	if err != nil {
		return nil, err
	}

	// this should never happen, but since this dictates how our calls into the
	// aes package behave and could be catastraphic, let's sanity check this
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid AES-256 key length (%d) - cowardly refusing to encrypt", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	blob := joinNonceCiphertext(nonce, ciphertext)

	return blob, nil
}

// Decrypts data using AES-256-GCM and the Argon2id key derivation function
// Expects the data to include an Argon2id parameter string before the encrypted data
func aes256Decrypt(passphrase []byte, kdfParams *Argon2Parameters, data []byte) ([]byte, error) {
	key, err := aes256DeriveKey(passphrase, kdfParams)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := splitNonceCiphertext(data, gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid passphrase or corrupt private key")
	}

	return plaintext, nil
}

func aes256DeriveKey(passphrase []byte, params *Argon2Parameters) ([]byte, error) {
	if params.salt == nil {
		params.salt = make([]byte, 32)
		if _, err := rand.Read(params.salt); err != nil {
			return nil, err
		}
	}

	// keySize of 32 bytes will result in AES-256 encryption
	key, err := deriveKey(passphrase, 32, params)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Derives a key from a passphrase using Argon2id
func deriveKey(passphrase []byte, keySize uint32, params *Argon2Parameters) ([]byte, error) {
	if params.version != argon2.Version {
		return nil, fmt.Errorf("incompatible Argon2 version: %d", params.version)
	}

	if params.salt == nil {
		return nil, fmt.Errorf("salt must be set in argon2Parameters")
	} else if len(params.salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 128  bits")
	}

	key := argon2.IDKey(passphrase, params.salt, params.Iterations, params.Memory, params.Parallelism, keySize)

	return key, nil
}

// Prepends nonce to ciphertext
func joinNonceCiphertext(nonce []byte, ciphertext []byte) []byte {
	return append(nonce, ciphertext...)
}

// Splits nonce from ciphertext
func splitNonceCiphertext(blob []byte, nonceSize int) ([]byte, []byte, error) {
	if len(blob) <= nonceSize {
		return nil, nil, fmt.Errorf("invalid ciphertext blob - blob shorter than nonce length")
	}

	return blob[:nonceSize], blob[nonceSize:], nil
}
