package cert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"
)

// Argon2Parameters KDF factors
type Argon2Parameters struct {
	version     rune
	Memory      uint32 // KiB
	Parallelism uint8
	Iterations  uint32
	salt        []byte
}

// NewArgon2Parameters Returns a new Argon2Parameters object with current version set
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

// EncryptAndMarshalSigningPrivateKey is a simple helper to encrypt and PEM encode a private key
func EncryptAndMarshalSigningPrivateKey(curve Curve, b []byte, passphrase []byte, kdfParams *Argon2Parameters) ([]byte, error) {
	ciphertext, err := aes256Encrypt(passphrase, kdfParams, b)
	if err != nil {
		return nil, err
	}

	b, err = proto.Marshal(&RawNebulaEncryptedData{
		EncryptionMetadata: &RawNebulaEncryptionMetadata{
			EncryptionAlgorithm: "AES-256-GCM",
			Argon2Parameters: &RawNebulaArgon2Parameters{
				Version:     kdfParams.version,
				Memory:      kdfParams.Memory,
				Parallelism: uint32(kdfParams.Parallelism),
				Iterations:  kdfParams.Iterations,
				Salt:        kdfParams.salt,
			},
		},
		Ciphertext: ciphertext,
	})
	if err != nil {
		return nil, err
	}

	switch curve {
	case Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: EncryptedEd25519PrivateKeyBanner, Bytes: b}), nil
	case Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: EncryptedECDSAP256PrivateKeyBanner, Bytes: b}), nil
	default:
		return nil, fmt.Errorf("invalid curve: %v", curve)
	}
}

// UnmarshalNebulaEncryptedData will unmarshal a protobuf byte representation of a nebula cert into its
// protobuf-generated struct.
func UnmarshalNebulaEncryptedData(b []byte) (*NebulaEncryptedData, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("nil byte array")
	}
	var rned RawNebulaEncryptedData
	err := proto.Unmarshal(b, &rned)
	if err != nil {
		return nil, err
	}

	if rned.EncryptionMetadata == nil {
		return nil, fmt.Errorf("encoded EncryptionMetadata was nil")
	}

	if rned.EncryptionMetadata.Argon2Parameters == nil {
		return nil, fmt.Errorf("encoded Argon2Parameters was nil")
	}

	params, err := unmarshalArgon2Parameters(rned.EncryptionMetadata.Argon2Parameters)
	if err != nil {
		return nil, err
	}

	ned := NebulaEncryptedData{
		EncryptionMetadata: NebulaEncryptionMetadata{
			EncryptionAlgorithm: rned.EncryptionMetadata.EncryptionAlgorithm,
			Argon2Parameters:    *params,
		},
		Ciphertext: rned.Ciphertext,
	}

	return &ned, nil
}

func unmarshalArgon2Parameters(params *RawNebulaArgon2Parameters) (*Argon2Parameters, error) {
	if params.Version < math.MinInt32 || params.Version > math.MaxInt32 {
		return nil, fmt.Errorf("Argon2Parameters Version must be at least %d and no more than %d", math.MinInt32, math.MaxInt32)
	}
	if params.Memory <= 0 || params.Memory > math.MaxUint32 {
		return nil, fmt.Errorf("Argon2Parameters Memory must be be greater than 0 and no more than %d KiB", uint32(math.MaxUint32))
	}
	if params.Parallelism <= 0 || params.Parallelism > math.MaxUint8 {
		return nil, fmt.Errorf("Argon2Parameters Parallelism must be be greater than 0 and no more than %d", math.MaxUint8)
	}
	if params.Iterations <= 0 || params.Iterations > math.MaxUint32 {
		return nil, fmt.Errorf("-argon-iterations must be be greater than 0 and no more than %d", uint32(math.MaxUint32))
	}

	return &Argon2Parameters{
		version:     params.Version,
		Memory:      params.Memory,
		Parallelism: uint8(params.Parallelism),
		Iterations:  params.Iterations,
		salt:        params.Salt,
	}, nil

}

// DecryptAndUnmarshalSigningPrivateKey will try to pem decode and decrypt an Ed25519/ECDSA private key with
// the given passphrase, returning any other bytes b or an error on failure
func DecryptAndUnmarshalSigningPrivateKey(passphrase, b []byte) (Curve, []byte, []byte, error) {
	var curve Curve

	k, r := pem.Decode(b)
	if k == nil {
		return curve, nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}

	switch k.Type {
	case EncryptedEd25519PrivateKeyBanner:
		curve = Curve_CURVE25519
	case EncryptedECDSAP256PrivateKeyBanner:
		curve = Curve_P256
	default:
		return curve, nil, r, fmt.Errorf("bytes did not contain a proper nebula encrypted Ed25519/ECDSA private key banner")
	}

	ned, err := UnmarshalNebulaEncryptedData(k.Bytes)
	if err != nil {
		return curve, nil, r, err
	}

	var bytes []byte
	switch ned.EncryptionMetadata.EncryptionAlgorithm {
	case "AES-256-GCM":
		bytes, err = aes256Decrypt(passphrase, &ned.EncryptionMetadata.Argon2Parameters, ned.Ciphertext)
		if err != nil {
			return curve, nil, r, err
		}
	default:
		return curve, nil, r, fmt.Errorf("unsupported encryption algorithm: %s", ned.EncryptionMetadata.EncryptionAlgorithm)
	}

	switch curve {
	case Curve_CURVE25519:
		if len(bytes) != ed25519.PrivateKeySize {
			return curve, nil, r, fmt.Errorf("key was not %d bytes, is invalid ed25519 private key", ed25519.PrivateKeySize)
		}
	case Curve_P256:
		if len(bytes) != 32 {
			return curve, nil, r, fmt.Errorf("key was not 32 bytes, is invalid ECDSA P256 private key")
		}
	}

	return curve, bytes, r, nil
}
