package cert

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Key size of 32 will result in AES-256
const keySize = 32

// KDF factors
type argon2Parameters struct {
	memory      uint32 // KiB
	iterations  uint32
	parallelism uint8
	salt        []byte
}

// Encrypts data using AES-256-GCM and the Argon2id key derivation function
func encrypt(passphrase, data []byte) ([]byte, error) {
	// KDF factors - roughly 250ms on a 2019 Macbook Pro
	params := argon2Parameters{
		memory:      64 * 1024,
		iterations:  24,
		parallelism: 8,
	}

	// This function call will set params.salt
	key, err := deriveKey(passphrase, &params)
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	blob := joinNonceCiphertext(nonce, ciphertext)

	// Results in something like: $argon2id$v=19$m=65536,t=24,p=8$SALT$nonceCIPHERTEXT
	return encodeParameters(argon2.Version, params, blob), nil
}

// Decrypts data using AES-256-GCM and the Argon2id key derivation function
// Expects the data to include an Argon2id parameter string before the encrypted data
func decrypt(passphrase, data []byte) ([]byte, error) {
	params, rest, err := decodeParameters(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing parameters for decryption: %s", err)
	}

	key, err := deriveKey(passphrase, params)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)

	nonce, ciphertext, err := splitNonceCiphertext(rest, gcm.NonceSize())
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid passphrase or corrupt private key")
	}

	return plaintext, nil
}

// Derives a key from a passphrase using Argon2id
func deriveKey(passphrase []byte, params *argon2Parameters) ([]byte, error) {
	if params.salt == nil {
		params.salt = make([]byte, 32)
		if _, err := rand.Read(params.salt); err != nil {
			return nil, err
		}
	}

	key := argon2.IDKey(passphrase, params.salt, params.iterations, params.memory, params.parallelism, keySize)

	return key, nil
}

// Encodes the Argon2id parameters used to derive the encryption key as a string
func encodeParameters(version rune, params argon2Parameters, blob []byte) []byte {
	b64Salt := base64.RawStdEncoding.EncodeToString(params.salt)
	// This format can be found in the Argon2 CLI tool and other libraries.
	// Typically it would include one more $ followed by the hash itself.
	// Since the hash is our decryption key, we don't actually want to save it.
	// Instead, we'll stick our ciphertext blob at the end.
	return bytes.Join([][]byte{
		[]byte(fmt.Sprintf(
			"$argon2id$v=%d$m=%d,t=%d,p=%d$%s",
			version, params.memory, params.iterations, params.parallelism, b64Salt,
		)),
		blob,
	}, []byte("$"))
}

// Decodes an Argon2id parameter string into a struct and returns any appended data
func decodeParameters(data []byte) (*argon2Parameters, []byte, error) {
	vals := strings.SplitN(string(data), "$", 6)
	// This will ensure that we have not only enough data to decode parameters,
	// but that there is also additional ciphertext that follows.
	if len(vals) != 6 {
		return nil, nil, fmt.Errorf("invalid data - does not contain enough parameters for Argon2id")
	}

	if vals[1] != "argon2id" {
		return nil, nil, fmt.Errorf("invalid data - algorithm is not argon2id: %s", vals[1])
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid data while scanning: %s", err)
	}

	var params argon2Parameters
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid data while scanning: %s", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing salt: %s", err)
	}
	params.salt = salt

	return &params, []byte(vals[5]), nil
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
