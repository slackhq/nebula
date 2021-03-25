package cert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KDF factors
type argon2Parameters struct {
	version     rune
	memory      uint32 // KiB
	iterations  uint32
	parallelism uint8
	salt        []byte
}

// Encodes Argon2Parameters, used for deriving a key, as a string
func (p *argon2Parameters) String() string {
	b64Salt := base64.RawStdEncoding.EncodeToString(p.salt)

	// This format can be found in the Argon2 CLI tool and other libraries.
	// For password storage, the password hash would appear at the end as well.
	// In our case, since the hash is our decryption key, we do not include it.
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s",
		p.version, p.memory, p.iterations, p.parallelism, b64Salt,
	)
}

// Decode Argon2Parameters, used for deriving a key, from a string
func argon2ParametersFromString(data string) (*argon2Parameters, error) {
	vals := strings.SplitN(data, "$", 5)
	if len(vals) != 5 {
		return nil, fmt.Errorf("invalid data - does not contain enough parameters for Argon2id")
	}

	if vals[1] != "argon2id" {
		return nil, fmt.Errorf("unexpected data - algorithm is not argon2id: %s", vals[1])
	}

	var params argon2Parameters

	_, err := fmt.Sscanf(vals[2], "v=%d", &params.version)
	if err != nil {
		return nil, fmt.Errorf("invalid data while scanning: %s", err)
	}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		return nil, fmt.Errorf("invalid data while scanning: %s", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, fmt.Errorf("error parsing salt: %s", err)
	}
	params.salt = salt

	return &params, nil
}

// Encrypts data using AES-256-GCM and the Argon2id key derivation function
func aes256Encrypt(passphrase, data []byte) ([]byte, string, error) {
	key, params, err := aes256DeriveKey(passphrase, nil)
	if err != nil {
		return nil, "", err
	}

	// this should never happen, but since this dictates how our calls into the
	// aes package behave and could be catastraphic, let's sanity check this
	if len(key) != 32 {
		return nil, "", fmt.Errorf("invalid AES-256 key length (%d) - cowardly refusing to encrypt", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	blob := joinNonceCiphertext(nonce, ciphertext)

	// Results in something like: nonceCIPHERTEXT, $argon2id$v=19$m=65536,t=24,p=8$SALT
	return blob, params.String(), nil
}

// Decrypts data using AES-256-GCM and the Argon2id key derivation function
// Expects the data to include an Argon2id parameter string before the encrypted data
func aes256Decrypt(passphrase, data []byte, kdfParams string) ([]byte, error) {
	params, err := argon2ParametersFromString(kdfParams)
	if err != nil {
		return nil, fmt.Errorf("error parsing parameters for decryption: %s", err)
	}

	key, params, err := aes256DeriveKey(passphrase, params)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)

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

func aes256DeriveKey(passphrase []byte, params *argon2Parameters) ([]byte, *argon2Parameters, error) {
	if params == nil {
		params = &argon2Parameters{
			version:     argon2.Version,
			memory:      2 * 1024 * 1024, // 2 GiB
			iterations:  3,
			parallelism: 4,
		}
	}

	if params.salt == nil {
		params.salt = make([]byte, 32)
		if _, err := rand.Read(params.salt); err != nil {
			return nil, nil, err
		}
	}

	// keySize of 32 bytes will result in AES-256 encryption
	key, err := deriveKey(passphrase, 32, params)
	if err != nil {
		return nil, nil, err
	}

	return key, params, nil
}

// Derives a key from a passphrase using Argon2id
func deriveKey(passphrase []byte, keySize uint32, params *argon2Parameters) ([]byte, error) {
	if params.version != argon2.Version {
		return nil, fmt.Errorf("incompatible Argon2 version: %d", params.version)
	}

	if params.salt == nil {
		return nil, fmt.Errorf("salt must be set in argon2Parameters")
	}

	key := argon2.IDKey(passphrase, params.salt, params.iterations, params.memory, params.parallelism, keySize)

	return key, nil
}

func joinNonceCiphertext(nonce []byte, ciphertext []byte) []byte {
	return append(nonce, ciphertext...)
}

// Splits nonce from ciphertext on data which has had KDF params removed
func splitNonceCiphertext(blob []byte, nonceSize int) ([]byte, []byte, error) {
	if len(blob) <= nonceSize {
		return nil, nil, fmt.Errorf("ciphertext blob does not contain nonce")
	}

	return blob[:nonceSize], blob[nonceSize:], nil
}
