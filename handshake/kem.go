package handshake

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"errors"
	"fmt"
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
