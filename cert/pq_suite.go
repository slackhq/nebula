package cert

import (
	"crypto/mldsa"
	"crypto/mlkem"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// PQSuite names the post-quantum algorithms of a version 3 certificate, the way Curve names its classical ones: the
// key encapsulation mechanism of a host's key, and the signature algorithm of a CA's key and of the certificates it
// signs. A CA and every certificate it signs share a suite. Every version 3 certificate names its suite.
type PQSuite uint8

const (
	// PQSuiteUnknown is never valid in a certificate.
	PQSuiteUnknown PQSuite = 0

	// PQSuite_MLKEM1024_MLDSA87 gives hosts ML-KEM-1024 keys and CAs ML-DSA-87 keys and signatures.
	PQSuite_MLKEM1024_MLDSA87 PQSuite = 1
)

// DefaultPQSuite is the suite tools use when none is asked for.
const DefaultPQSuite = PQSuite_MLKEM1024_MLDSA87

// pqKEM is the key encapsulation mechanism of a suite, what host keys use. Private keys are seeds.
type pqKEM struct {
	name           string // as it appears in key banners
	publicKeySize  int
	privateKeySize int
	generate       func() (pub, priv []byte, err error)
	publicKey      func(priv []byte) ([]byte, error)
	checkPublicKey func(pub []byte) bool
}

// pqDSA is the signature algorithm of a suite, what CA keys and certificate signatures use. Private keys are seeds.
type pqDSA struct {
	name           string // as it appears in key banners
	publicKeySize  int
	privateKeySize int
	signatureSize  int
	generate       func() (pub, priv []byte, err error)
	publicKey      func(priv []byte) ([]byte, error)
	checkPublicKey func(pub []byte) bool
	signer         func(priv []byte, ctx string) (SignerLambda, error) // must sign deterministically
	verify         func(pub, msg, sig []byte, ctx string) bool
}

type pqSuite struct {
	kem pqKEM
	dsa pqDSA

	// available is nil when this build has both algorithms. Some do not: the FIPS 140-3 Go Cryptographic Module
	// v1.0.0 has ML-KEM but no ML-DSA, and every ML-DSA call fails.
	available func() error
}

// pqSuites holds every known suite, see registerPQSuite.
var pqSuites = map[PQSuite]*pqSuite{}

func init() {
	registerPQSuite(PQSuite_MLKEM1024_MLDSA87, &pqSuite{kem: mlkem1024, dsa: mldsa87})
}

// registerPQSuite makes a suite known, along with the banners of its composite keys.
func registerPQSuite(id PQSuite, s *pqSuite) {
	s.available = sync.OnceValue(func() error {
		if _, err := s.kem.publicKey(make([]byte, s.kem.privateKeySize)); err != nil {
			return fmt.Errorf("%w: %v: %w", ErrPQUnavailable, id, err)
		}
		if _, err := s.dsa.publicKey(make([]byte, s.dsa.privateKeySize)); err != nil {
			return fmt.Errorf("%w: %v: %w", ErrPQUnavailable, id, err)
		}
		return nil
	})
	pqSuites[id] = s
	for _, curve := range []Curve{Curve_CURVE25519, Curve_P256} {
		for _, kind := range pqKeyKinds {
			pqKeyBanners[pqBannerName(kind, curve, s)] = pqKeyBanner{kind: kind, curve: curve, size: pqKeySize(kind, curve, s)}
		}
	}
}

var mlkem1024 = pqKEM{
	name:           "MLKEM1024",
	publicKeySize:  mlkem.EncapsulationKeySize1024,
	privateKeySize: mlkem.SeedSize,
	generate: func() ([]byte, []byte, error) {
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, nil, err
		}
		return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
	},
	publicKey: func(priv []byte) ([]byte, error) {
		dk, err := mlkem.NewDecapsulationKey1024(priv)
		if err != nil {
			return nil, err
		}
		return dk.EncapsulationKey().Bytes(), nil
	},
	checkPublicKey: func(pub []byte) bool {
		return len(pub) == mlkem.EncapsulationKeySize1024 && mlkemModulusOK(pub[:len(pub)-32])
	},
}

// mlkemModulusOK is the modulus check of FIPS 203 section 7.2, the one crypto/mlkem runs on an encapsulation key: t,
// the key less its trailing 32 byte seed, packs 12 bit coefficients that must all be below q. crypto/mlkem would also
// expand the seed into the ~10KB matrix of an encapsulation key, which a certificate check has no use for.
func mlkemModulusOK(t []byte) bool {
	const q = 3329
	for i := 0; i+3 <= len(t); i += 3 {
		d1 := uint16(t[i]) | uint16(t[i+1]&0x0f)<<8
		d2 := uint16(t[i+1]>>4) | uint16(t[i+2])<<4
		if d1 >= q || d2 >= q {
			return false
		}
	}
	return true
}

var mldsa87 = pqDSA{
	name:           "MLDSA87",
	publicKeySize:  mldsa.MLDSA87PublicKeySize,
	privateKeySize: mldsa.PrivateKeySize,
	signatureSize:  mldsa.MLDSA87SignatureSize,
	generate: func() ([]byte, []byte, error) {
		sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
		if err != nil {
			return nil, nil, err
		}
		return sk.PublicKey().Bytes(), sk.Bytes(), nil
	},
	publicKey: func(priv []byte) ([]byte, error) {
		sk, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), priv)
		if err != nil {
			return nil, err
		}
		return sk.PublicKey().Bytes(), nil
	},
	checkPublicKey: func(pub []byte) bool {
		_, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pub)
		return err == nil
	},
	// Deterministic signing (FIPS 204 section 3.4): the hedged variant guards signers an attacker can fault
	// physically, which a CA key in a file is not, and the Ed25519 signature beside it is deterministic too.
	signer: func(priv []byte, ctx string) (SignerLambda, error) {
		sk, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), priv)
		if err != nil {
			return nil, err
		}
		return func(b []byte) ([]byte, error) {
			return sk.SignDeterministic(b, &mldsa.Options{Context: ctx})
		}, nil
	},
	verify: func(pub, msg, sig []byte, ctx string) bool {
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pub)
		if err != nil {
			return false
		}
		return mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: ctx}) == nil
	},
}

// PQSuites returns every known suite.
func PQSuites() []PQSuite {
	s := make([]PQSuite, 0, len(pqSuites))
	for k := range pqSuites {
		s = append(s, k)
	}
	slices.Sort(s)
	return s
}

// ParsePQSuite returns the suite named by s, as String names it, ignoring case.
func ParsePQSuite(s string) (PQSuite, error) {
	for _, k := range PQSuites() {
		if strings.EqualFold(s, k.String()) {
			return k, nil
		}
	}
	return PQSuiteUnknown, fmt.Errorf("%w: %q", ErrUnknownPQSuite, s)
}

// PQSuiteOf returns the suite of a version 3 certificate, or PQSuiteUnknown for any other version.
func PQSuiteOf(c Certificate) PQSuite {
	if c3, ok := c.(*certificateV3); ok {
		return c3.pqSuite
	}
	return PQSuiteUnknown
}

func (s PQSuite) String() string {
	if p := pqSuites[s]; p != nil {
		return p.kem.name + "_" + p.dsa.name
	}
	return fmt.Sprintf("PQSuite(%d)", uint8(s))
}

// Available returns an error wrapping ErrPQUnavailable, and the algorithm's own, when this build can not run the
// suite's algorithms, as with ML-DSA under the FIPS 140-3 Go Cryptographic Module v1.0.0.
func (s PQSuite) Available() error {
	p := pqSuites[s]
	if p == nil {
		return fmt.Errorf("%w: %v", ErrUnknownPQSuite, s)
	}
	return p.available()
}

// Valid reports whether s is a known suite.
func (s PQSuite) Valid() bool {
	return pqSuites[s] != nil
}

// PublicKeySize returns the size of the post-quantum half of a composite public key, a CA's or a host's.
func (s PQSuite) PublicKeySize(isCA bool) int {
	p := pqSuites[s]
	switch {
	case p == nil:
		return 0
	case isCA:
		return p.dsa.publicKeySize
	default:
		return p.kem.publicKeySize
	}
}

// PrivateKeySize returns the size of the post-quantum half of a composite private key, a CA's or a host's.
func (s PQSuite) PrivateKeySize(isCA bool) int {
	p := pqSuites[s]
	switch {
	case p == nil:
		return 0
	case isCA:
		return p.dsa.privateKeySize
	default:
		return p.kem.privateKeySize
	}
}

// GenerateKey makes a post-quantum keypair, a CA's signing key or a host's KEM key, to append to a classical one.
func (s PQSuite) GenerateKey(isCA bool) (pub, priv []byte, err error) {
	p := pqSuites[s]
	switch {
	case p == nil:
		return nil, nil, fmt.Errorf("%w: %v", ErrUnknownPQSuite, s)
	case isCA:
		return p.dsa.generate()
	default:
		return p.kem.generate()
	}
}

// DerivePublicKey returns the post-quantum public key of the post-quantum half of a private key, a CA's or a host's.
func (s PQSuite) DerivePublicKey(isCA bool, priv []byte) ([]byte, error) {
	return s.publicKey(isCA, priv)
}

// publicKey derives the post-quantum public key from the post-quantum half of a private key.
func (s PQSuite) publicKey(isCA bool, priv []byte) ([]byte, error) {
	p := pqSuites[s]
	switch {
	case p == nil:
		return nil, fmt.Errorf("%w: %v", ErrUnknownPQSuite, s)
	case isCA:
		return p.dsa.publicKey(priv)
	default:
		return p.kem.publicKey(priv)
	}
}

// checkPublicKey reports whether pub is a well formed post-quantum public key, a CA's or a host's.
func (s PQSuite) checkPublicKey(isCA bool, pub []byte) bool {
	p := pqSuites[s]
	switch {
	case p == nil, len(pub) != s.PublicKeySize(isCA):
		return false
	case isCA:
		return p.dsa.checkPublicKey(pub)
	default:
		return p.kem.checkPublicKey(pub)
	}
}

// SignatureLabel names the pair of signature algorithms that sign a version 3 certificate of this suite and curve, the
// Label of the composite signature, see signedMessage. It is "" for an unknown suite or curve.
//
// draft-ietf-lamps-pq-composite-sigs fixes its labels and registers no pair of ML-DSA-87 with Ed25519 or ECDSA P256,
// so these are nebula's own, in its style.
func (s PQSuite) SignatureLabel(curve Curve) string {
	p := pqSuites[s]
	classical := map[Curve]string{Curve_CURVE25519: "Ed25519", Curve_P256: "ECDSA-P256"}[curve]
	if p == nil || classical == "" {
		return ""
	}
	return "NEBULA-CERTV3-" + p.dsa.name + "-" + classical + "-SHA512"
}

// signatureSize returns the size of the post-quantum signature of a certificate in this suite.
func (s PQSuite) signatureSize() int {
	if p := pqSuites[s]; p != nil {
		return p.dsa.signatureSize
	}
	return 0
}

// SplitPublicKey splits a composite public key into its classical and post-quantum halves.
func (s PQSuite) SplitPublicKey(isCA bool, key []byte) (classical, pq []byte, err error) {
	n := s.PublicKeySize(isCA)
	if n == 0 || len(key) <= n {
		return nil, nil, ErrInvalidPublicKey
	}
	return key[:len(key)-n], key[len(key)-n:], nil
}

// SplitPrivateKey splits a composite private key into its classical and post-quantum halves.
func (s PQSuite) SplitPrivateKey(isCA bool, key []byte) (classical, pq []byte, err error) {
	n := s.PrivateKeySize(isCA)
	if n == 0 || len(key) <= n {
		return nil, nil, ErrInvalidPrivateKey
	}
	return key[:len(key)-n], key[len(key)-n:], nil
}
