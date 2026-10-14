package handshake

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/DefinedNet/noise"
)

// kemPSKSalt separates the psk derivation from any other use of the secret.
const kemPSKSalt = "nebula ix_psk2_mlkem1024 v1"

var ErrInvalidKEMKey = errors.New("peer sent an invalid ML-KEM encapsulation key")

// kemPSK derives the noise psk from an ML-KEM shared secret. The ciphertext is
// bound in because, unlike the encapsulation key, it travels outside the noise
// transcript.
func kemPSK(sharedKey, ciphertext []byte) ([]byte, error) {
	secret := make([]byte, 0, len(sharedKey)+len(ciphertext))
	secret = append(secret, sharedKey...)
	secret = append(secret, ciphertext...)
	return hkdf.Extract(sha256.New, secret, []byte(kemPSKSalt))
}

// kemEncapsulate is the responder half: encapsulate to the initiator's key,
// install the psk, and remember the ciphertext to prefix the response with.
func (m *Machine) kemEncapsulate(encapsulationKey []byte) error {
	ek, err := mlkem.NewEncapsulationKey1024(encapsulationKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKEMKey, err)
	}
	sharedKey, ct := ek.Encapsulate()
	psk, err := kemPSK(sharedKey, ct)
	if err != nil {
		return err
	}
	if err := m.hs.SetPresharedKey(psk); err != nil {
		return err
	}
	m.kemCiphertext = ct
	return nil
}

// kemDecapsulate is the initiator half: recover the shared secret from the
// ciphertext prefixing the response and install the psk. It returns the rest of
// the message, which is the noise message.
func (m *Machine) kemDecapsulate(msg []byte) ([]byte, error) {
	if len(msg) < mlkem.CiphertextSize1024 {
		return nil, ErrPacketTooShort
	}
	if m.kemKey == nil {
		return nil, errors.New("no ML-KEM decapsulation key for this handshake")
	}
	ct := msg[:mlkem.CiphertextSize1024]
	sharedKey, err := m.kemKey.Decapsulate(ct)
	if err != nil {
		return nil, err
	}
	psk, err := kemPSK(sharedKey, ct)
	if err != nil {
		return nil, err
	}
	if err := m.hs.SetPresharedKey(psk); err != nil {
		return nil, err
	}
	return msg[mlkem.CiphertextSize1024:], nil
}

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
