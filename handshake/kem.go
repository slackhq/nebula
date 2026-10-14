package handshake

import (
	"crypto/mlkem"
	"crypto/subtle"
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

// mlkem1024Keys is KEMMLKEM1024 for one handshake. It decapsulates with the
// keys it holds expanded, the static one from the Credential and the ephemeral
// one it generated, rather than expanding them again from the seeds noise hands
// back; any other private key is expanded as usual.
type mlkem1024Keys struct {
	kemMLKEM1024
	static        *mlkem.DecapsulationKey1024
	staticSeed    []byte
	ephemeral     *mlkem.DecapsulationKey1024
	ephemeralSeed []byte
}

func (k *mlkem1024Keys) GenerateKeypair(_ io.Reader) (noise.KEMKey, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return noise.KEMKey{}, fmt.Errorf("mlkem1024: GenerateKey: %w", err)
	}
	k.ephemeral, k.ephemeralSeed = dk, dk.Bytes()
	return noise.KEMKey{Private: k.ephemeralSeed, Public: dk.EncapsulationKey().Bytes()}, nil
}

func (k *mlkem1024Keys) Decapsulate(privkey, ciphertext []byte) ([]byte, error) {
	switch {
	case k.static != nil && subtle.ConstantTimeCompare(privkey, k.staticSeed) == 1:
		return k.static.Decapsulate(ciphertext)
	case k.ephemeral != nil && subtle.ConstantTimeCompare(privkey, k.ephemeralSeed) == 1:
		return k.ephemeral.Decapsulate(ciphertext)
	}
	return k.kemMLKEM1024.Decapsulate(privkey, ciphertext)
}

func (kemMLKEM1024) PublicKeyLen() int  { return mlkem.EncapsulationKeySize1024 }
func (kemMLKEM1024) CiphertextLen() int { return mlkem.CiphertextSize1024 }
func (kemMLKEM1024) KEMName() string    { return "MLKEM1024" }
