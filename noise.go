package nebula

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/flynn/noise"
)

type endianness interface {
	PutUint64(b []byte, v uint64)
}

var noiseEndianness endianness = binary.BigEndian

// NonceSize is the AEAD nonce length used by all ciphers nebula supports
// today (AES-GCM and ChaCha20-Poly1305 both use 96-bit nonces). Encrypt-
// and DecryptDanger lay out the nonce as 4 zero bytes followed by an 8-byte
// big-endian counter; if a future cipher with a different nonce size is
// added, this constant and those layouts must change together.
const NonceSize = 12

// AEADOverhead is the AEAD authentication tag length the ciphers nebula
// supports append to ciphertext. Both AES-GCM and ChaCha20-Poly1305 use
// 128-bit tags. NebulaCipherState.Overhead() returns this dynamically from
// the cipher; the constant is for sizing buffers at construction time.
const AEADOverhead = 16

type NebulaCipherState struct {
	c cipher.AEAD
}

func NewNebulaCipherState(s *noise.CipherState) *NebulaCipherState {
	x := s.Cipher()
	return &NebulaCipherState{c: x.(cipher.AEAD)}
}

// EncryptDanger encrypts and authenticates a given payload.
//
// out is a destination slice to hold the output of the EncryptDanger operation.
//   - ad is additional data, which will be authenticated and appended to out, but not encrypted.
//   - plaintext is encrypted, authenticated and appended to out.
//   - n is a nonce value which must never be re-used with this key.
//   - nb is a buffer used for temporary storage in the implementation of this call, which should
//     be re-used by callers to minimize garbage collection.
func (s *NebulaCipherState) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	if s != nil {
		// TODO: Is this okay now that we have made messageCounter atomic?
		// Alternative may be to split the counter space into ranges
		//if n <= s.n {
		//	return nil, errors.New("CRITICAL: a duplicate counter value was used")
		//}
		//s.n = n
		nb[0] = 0
		nb[1] = 0
		nb[2] = 0
		nb[3] = 0
		noiseEndianness.PutUint64(nb[4:], n)
		out = s.c.Seal(out, nb, plaintext, ad)
		//l.Debugf("Encryption: outlen: %d, nonce: %d, ad: %s, plainlen %d", len(out), n, ad, len(plaintext))
		return out, nil
	} else {
		return nil, errors.New("no cipher state available to encrypt")
	}
}

func (s *NebulaCipherState) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	if s != nil {
		nb[0] = 0
		nb[1] = 0
		nb[2] = 0
		nb[3] = 0
		noiseEndianness.PutUint64(nb[4:], n)
		return s.c.Open(out, nb, ciphertext, ad)
	} else {
		return []byte{}, nil
	}
}

func (s *NebulaCipherState) Overhead() int {
	if s != nil {
		return s.c.Overhead()
	}
	return 0
}
