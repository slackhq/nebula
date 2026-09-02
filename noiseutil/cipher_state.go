package noiseutil

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"math"

	"github.com/flynn/noise"
)

// RejectHeadroom is the wrap gap for senders racing the counter, sized large enough for any routine count.
const RejectHeadroom = uint64(1) << 40

// RejectAfterMessages is the nonce ceiling: encrypting stops RejectHeadroom short of the wrap.
const RejectAfterMessages = math.MaxUint64 - RejectHeadroom

// ErrMessageCounterExhausted is returned by EncryptDanger once the nonce reaches RejectAfterMessages.
var ErrMessageCounterExhausted = errors.New("message counter exhausted")

// CipherState is the post-handshake AEAD cipher used for the data plane.
// Each supported cipher has its own concrete implementation in this package with the nonce endianness hardcoded,
// so the encrypt/decrypt fast path avoids interface dispatch on the byte order.
type CipherState interface {
	// EncryptDanger encrypts and authenticates a given payload.
	//
	// out is a destination slice to hold the output of the EncryptDanger operation.
	//   - ad is additional data, which will be authenticated and appended to out, but not encrypted.
	//   - plaintext is encrypted, authenticated and appended to out.
	//   - n is a nonce value which must never be re-used with this key.
	//   - nb is a scratch buffer used to assemble the nonce.
	EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error)

	// DecryptDanger authenticates and decrypts a given payload, with the same argument shape as EncryptDanger.
	DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error)

	// Overhead returns the AEAD tag size, or 0 if the receiver is nil.
	Overhead() int
}

// NewCipherState wraps the post-handshake noise.CipherState in the per-cipher type that matches cipherFunc.
// cipherFunc must be the same cipher used to build the noise CipherSuite that produced s.
func NewCipherState(s *noise.CipherState, cipherFunc noise.CipherFunc) CipherState {
	if cs, ok := s.Cipher().(CipherState); ok {
		return cs
	}
	switch cipherFunc.CipherName() {
	case noise.CipherAESGCM.CipherName():
		return NewCipherStateAESGCM(s)
	case noise.CipherChaChaPoly.CipherName():
		return NewCipherStateChaChaPoly(s)
	default:
		panic(fmt.Sprintf("noiseutil: unsupported cipher %q", cipherFunc.CipherName()))
	}
}

// NewCipherStateFromKey builds a data-plane CipherState directly from raw key
// bytes, bypassing the noise handshake. Multiport lanes use this to key a
// derived session off the base tunnel's negotiated keys; the caller owns the
// guarantee that key is used with exactly one CipherState so nonces never
// repeat.
func NewCipherStateFromKey(key [32]byte, cipherFunc noise.CipherFunc) CipherState {
	c := cipherFunc.Cipher(key)
	if cs, ok := c.(CipherState); ok {
		return cs
	}

	aead, ok := c.(cipher.AEAD)
	if !ok {
		panic(fmt.Sprintf("noiseutil: cipher %q does not expose an AEAD", cipherFunc.CipherName()))
	}

	switch cipherFunc.CipherName() {
	case noise.CipherAESGCM.CipherName():
		return &CipherStateAESGCM{c: aead}
	case noise.CipherChaChaPoly.CipherName():
		return &CipherStateChaChaPoly{c: aead}
	default:
		panic(fmt.Sprintf("noiseutil: unsupported cipher %q", cipherFunc.CipherName()))
	}
}
