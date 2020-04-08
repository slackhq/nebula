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

type NebulaCipherState struct {
	c noise.Cipher
	//k [32]byte
	//n uint64
}

func NewNebulaCipherState(s *noise.CipherState) *NebulaCipherState {
	return &NebulaCipherState{c: s.Cipher()}

}

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
		out = s.c.(cipher.AEAD).Seal(out, nb, plaintext, ad)
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
		return s.c.(cipher.AEAD).Open(out, nb, ciphertext, ad)
	} else {
		return []byte{}, nil
	}
}
