package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"time"
)

// TBSCertificate represents a certificate intended to be signed.
// It is invalid to use this structure as a Certificate.
type TBSCertificate struct {
	Version        Version
	Name           string
	Networks       []netip.Prefix
	UnsafeNetworks []netip.Prefix
	Groups         []string
	IsCA           bool
	NotBefore      time.Time
	NotAfter       time.Time
	PublicKey      []byte
	Curve          Curve
	issuer         string
}

type beingSignedCertificate interface {
	// fromTBSCertificate copies the values from the TBSCertificate to this versions internal representation
	// Implementations must validate the resulting certificate contains valid information
	fromTBSCertificate(*TBSCertificate) error

	// marshalForSigning returns the bytes that should be signed
	marshalForSigning() ([]byte, error)

	// setSignature sets the signature for the certificate that has just been signed. The signature must not be blank.
	setSignature([]byte) error
}

type SignerLambda func(certBytes []byte) ([]byte, error)

// Sign will create a sealed certificate using details provided by the TBSCertificate as long as those
// details do not violate constraints of the signing certificate.
// If the TBSCertificate is a CA then signer must be nil.
func (t *TBSCertificate) Sign(signer Certificate, curve Curve, key []byte) (Certificate, error) {
	switch t.Curve {
	case Curve_CURVE25519:
		pk := ed25519.PrivateKey(key)
		sp := func(certBytes []byte) ([]byte, error) {
			sig := ed25519.Sign(pk, certBytes)
			return sig, nil
		}
		return t.SignWith(signer, curve, sp)
	case Curve_P256:
		pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
		if err != nil {
			return nil, err
		}
		sp := func(certBytes []byte) ([]byte, error) {
			// We need to hash first for ECDSA
			// - https://pkg.go.dev/crypto/ecdsa#SignASN1
			hashed := sha256.Sum256(certBytes)
			return ecdsa.SignASN1(rand.Reader, pk, hashed[:])
		}
		return t.SignWith(signer, curve, sp)
	default:
		return nil, fmt.Errorf("invalid curve: %s", t.Curve)
	}
}

// SignWith does the same thing as sign, but uses the function in `sp` to calculate the signature.
// You should only use SignWith if you do not have direct access to your private key.
func (t *TBSCertificate) SignWith(signer Certificate, curve Curve, sp SignerLambda) (Certificate, error) {
	if curve != t.Curve {
		return nil, fmt.Errorf("curve in cert and private key supplied don't match")
	}

	if signer != nil {
		if t.IsCA {
			return nil, fmt.Errorf("can not sign a CA certificate with another")
		}

		err := checkCAConstraints(signer, t.NotBefore, t.NotAfter, t.Groups, t.Networks, t.UnsafeNetworks)
		if err != nil {
			return nil, err
		}

		issuer, err := signer.Fingerprint()
		if err != nil {
			return nil, fmt.Errorf("error computing issuer: %v", err)
		}
		t.issuer = issuer
	} else {
		if !t.IsCA {
			return nil, fmt.Errorf("self signed certificates must have IsCA set to true")
		}
	}

	var c beingSignedCertificate
	switch t.Version {
	case Version1:
		c = &certificateV1{}
		err := c.fromTBSCertificate(t)
		if err != nil {
			return nil, err
		}
	case Version2:
		c = &certificateV2{}
		err := c.fromTBSCertificate(t)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown cert version %d", t.Version)
	}

	certBytes, err := c.marshalForSigning()
	if err != nil {
		return nil, err
	}

	sig, err := sp(certBytes)
	if err != nil {
		return nil, err
	}

	err = c.setSignature(sig)
	if err != nil {
		return nil, err
	}

	sc, ok := c.(Certificate)
	if !ok {
		return nil, fmt.Errorf("invalid certificate")
	}

	return sc, nil
}

func comparePrefix(a, b netip.Prefix) int {
	addr := a.Addr().Compare(b.Addr())
	if addr == 0 {
		return a.Bits() - b.Bits()
	}
	return addr
}

// findDuplicatePrefix returns an error if there is a duplicate prefix in the pre-sorted input slice sortedPrefixes
func findDuplicatePrefix(sortedPrefixes []netip.Prefix) error {
	if len(sortedPrefixes) < 2 {
		return nil
	}
	for i := 1; i < len(sortedPrefixes); i++ {
		if comparePrefix(sortedPrefixes[i], sortedPrefixes[i-1]) == 0 {
			return NewErrInvalidCertificateProperties("duplicate network detected: %v", sortedPrefixes[i])
		}
	}
	return nil
}
