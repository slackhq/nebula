package handshake

import (
	"crypto/mlkem"
	"errors"
	"fmt"
	"io"

	"github.com/DefinedNet/noise"
)

var ErrInvalidKEMKey = errors.New("peer sent an invalid ML-KEM encapsulation key")

// KEMMLKEM1024 is ML-KEM-1024 for the noise library's hybrid patterns. Private
// keys are the 64 byte seed, the same form v3 private keys store.
var KEMMLKEM1024 noise.KEMFunc = kemMLKEM1024{}

type kemMLKEM1024 struct{}

// GenerateKeypair ignores random, crypto/mlkem always draws from crypto/rand.
func (kemMLKEM1024) GenerateKeypair(_ io.Reader) (noise.KEMKey, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return noise.KEMKey{}, fmt.Errorf("mlkem1024: GenerateKey: %w", err)
	}
	return noise.KEMKey{Private: dk.Bytes(), Public: dk.EncapsulationKey().Bytes()}, nil
}

func (kemMLKEM1024) Encapsulate(pubkey []byte) ([]byte, []byte, error) {
	ek, err := mlkem.NewEncapsulationKey1024(pubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidKEMKey, err)
	}
	ss, ct := ek.Encapsulate()
	return ct, ss, nil
}

func (kemMLKEM1024) Decapsulate(privkey, ciphertext []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey1024(privkey)
	if err != nil {
		return nil, fmt.Errorf("mlkem1024: NewDecapsulationKey: %w", err)
	}
	return dk.Decapsulate(ciphertext)
}

func (kemMLKEM1024) PublicKeyLen() int  { return mlkem.EncapsulationKeySize1024 }
func (kemMLKEM1024) CiphertextLen() int { return mlkem.CiphertextSize1024 }
func (kemMLKEM1024) KEMName() string    { return "MLKEM1024" }
