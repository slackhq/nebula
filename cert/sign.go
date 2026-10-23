package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert/p256"
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
	PQSuite        PQSuite // version 3 only, the suite of the certificate and of its signing CA
	// OmitV2Form, version 3 only, signs a certificate without a v2 form, for v3 peers only. A CA without a v2 form can
	// only sign such certificates.
	OmitV2Form bool
	issuer     string
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
// key is the private key of signer, composite for a version 3 signer; a version 3 CA signs version 1 and 2
// certificates as its v2 form, with the key's classical half.
func (t *TBSCertificate) Sign(signer Certificate, curve Curve, key []byte) (Certificate, error) {
	if t.Version == Version3 {
		// The signing key is a composite CA key, classical || the seed of the suite's signature algorithm.
		classicalKey, pqKey, err := t.PQSuite.SplitPrivateKey(true, key)
		if err != nil {
			return nil, err
		}
		classical, err := SignClassical(t.Curve, classicalKey)
		if err != nil {
			return nil, err
		}
		pq, err := SignPQ(t.PQSuite, t.Curve, pqKey)
		if err != nil {
			return nil, err
		}
		return t.SignHybridWith(signer, curve, classical, pq)
	}

	// A version 3 CA signs older certificates as its v2 form, with the classical half of its composite key.
	if signer != nil && signer.Version() == Version3 {
		classicalKey, _, err := PQSuiteOf(signer).SplitPrivateKey(true, key)
		if err != nil {
			return nil, err
		}
		key = classicalKey
	}

	sp, err := classicalSigner(t.Curve, key)
	if err != nil {
		return nil, err
	}
	return t.SignWith(signer, curve, sp)
}

// classicalSigner returns a SignerLambda for a classical signing private key.
func classicalSigner(curve Curve, key []byte) (SignerLambda, error) {
	switch curve {
	case Curve_CURVE25519:
		if len(key) != ed25519.PrivateKeySize {
			return nil, ErrInvalidPrivateKey
		}
		pk := ed25519.PrivateKey(key)
		return func(certBytes []byte) ([]byte, error) {
			sig := ed25519.Sign(pk, certBytes)
			return sig, nil
		}, nil
	case Curve_P256:
		pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
		if err != nil {
			return nil, err
		}
		return func(certBytes []byte) ([]byte, error) {
			// We need to hash first for ECDSA
			// - https://pkg.go.dev/crypto/ecdsa#SignASN1
			hashed := sha256.Sum256(certBytes)
			return ecdsa.SignASN1(rand.Reader, pk, hashed[:])
		}, nil
	default:
		return nil, fmt.Errorf("invalid curve: %s", curve)
	}
}

// SignHybridWith signs a version 3 certificate, using sp for its classical signatures and pqSp for the post-quantum
// one of t.PQSuite. t.PublicKey is the composite public key. signer must be a version 3 CA in the same suite, or nil
// for a self signed CA. The v2 form is signed exactly as SignWith would sign it, and so is the v2 form of signer. sp
// then signs the whole certificate too, and pqSp signs it with t.PQSuite.SignatureLabel(curve) as its context, see
// SignClassical and SignPQ.
func (t *TBSCertificate) SignHybridWith(signer Certificate, curve Curve, sp, pqSp SignerLambda) (Certificate, error) {
	if t.Version != Version3 {
		return nil, fmt.Errorf("SignHybridWith only signs version 3 certificates")
	}
	if !t.PQSuite.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrUnknownPQSuite, t.PQSuite)
	}
	classical, pq, err := t.PQSuite.SplitPublicKey(t.IsCA, t.PublicKey)
	if err != nil {
		return nil, err
	}

	var signerV2 Certificate
	if signer != nil {
		if signer.Version() != Version3 {
			return nil, fmt.Errorf("a version 3 certificate must be signed by a version 3 CA")
		}
		if PQSuiteOf(signer) != t.PQSuite {
			return nil, ErrPQSuiteMismatch
		}
		signerV2 = V2Form(signer)
	}
	if t.OmitV2Form {
		return t.signWithoutV2Form(signer, curve, classical, pq, sp, pqSp)
	}
	if signer != nil && signerV2 == nil {
		return nil, ErrNoV2FormCA
	}

	t2 := *t
	t2.Version = Version2
	t2.PublicKey = classical
	c2, err := t2.SignWith(signerV2, curve, sp)
	if err != nil {
		return nil, err
	}
	return ExtendToV3(c2, t.PQSuite, pq, signer, sp, pqSp)
}

// signWithoutV2Form signs a version 3 certificate that has no v2 form: its details name no issuer and carry no v2
// signature, only the two signatures of the whole certificate.
func (t *TBSCertificate) signWithoutV2Form(signer Certificate, curve Curve, classical, pq []byte, sp, pqSp SignerLambda) (Certificate, error) {
	if curve != t.Curve {
		return nil, fmt.Errorf("curve in cert and private key supplied don't match")
	}

	signingKey := t.PublicKey
	var issuer string
	if signer != nil {
		if t.IsCA {
			return nil, fmt.Errorf("can not sign a CA certificate with another")
		}
		if err := checkCAConstraints(signer, t.NotBefore, t.NotAfter, t.Groups, t.Networks, t.UnsafeNetworks); err != nil {
			return nil, err
		}
		var err error
		if issuer, err = signer.Fingerprint(); err != nil {
			return nil, fmt.Errorf("error computing issuer: %v", err)
		}
		signingKey = signer.PublicKey()
	} else if !t.IsCA {
		return nil, fmt.Errorf("self signed certificates must have IsCA set to true")
	}

	t2 := *t
	t2.Version = Version2
	t2.PublicKey = classical
	t2.issuer = ""
	var c2 certificateV2
	if err := c2.fromTBSCertificate(&t2); err != nil {
		return nil, err
	}
	var err error
	if c2.rawDetails, err = c2.details.Marshal(); err != nil {
		return nil, fmt.Errorf("marshalling certificate details failed: %w", err)
	}

	c3 := &certificateV3{
		v2:          c2,
		pqSuite:     t.PQSuite,
		issuer:      issuer,
		pqPublicKey: bytes.Clone(pq),
	}
	return c3.sign(signingKey, sp, pqSp)
}

// SignWith does the same thing as sign, but uses the function in `sp` to calculate the signature.
// You should only use SignWith if you do not have direct access to your private key.
func (t *TBSCertificate) SignWith(signer Certificate, curve Curve, sp SignerLambda) (Certificate, error) {
	if curve != t.Curve {
		return nil, fmt.Errorf("curve in cert and private key supplied don't match")
	}

	// A version 3 CA signs older certificates as its v2 form, which is what their issuer has to name. sp must then
	// sign with the classical half of its key.
	if signer != nil && signer.Version() == Version3 && t.Version != Version3 {
		v2 := V2Form(signer)
		if v2 == nil {
			return nil, ErrNoV2FormCA
		}
		signer = v2
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
	case Version3:
		return nil, fmt.Errorf("version 3 certificates carry two signatures, use SignHybridWith")
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

	if curve == Curve_P256 {
		sig, err = p256.Normalize(sig)
		if err != nil {
			return nil, err
		}
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
