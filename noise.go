package nebula

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"
	"golang.org/x/crypto/hkdf"
)

type endiannes interface {
	PutUint64(b []byte, v uint64)
}

var noiseEndiannes endiannes = binary.BigEndian

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
		noiseEndiannes.PutUint64(nb[4:], n)
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
		noiseEndiannes.PutUint64(nb[4:], n)
		return s.c.(cipher.AEAD).Open(out, nb, ciphertext, ad)
	} else {
		return []byte{}, nil
	}
}

func sha256KdfFromString(secret string) ([]byte, error) {
	if len(secret) < 8 {
		err := ("PSK too short!")
		return nil, fmt.Errorf("%s", err)
	}
	hmacKey := make([]byte, sha256.Size)
	hash := sha256.New
	hkdfer := hkdf.New(hash, []byte(secret), nil, nil)
	n, err := io.ReadFull(hkdfer, hmacKey)
	if n != len(hmacKey) || err != nil {
		return nil, fmt.Errorf("%s", err)
	}
	return hmacKey, nil
}
