package cert

import (
	"bytes"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// A version 3 certificate is a version 2 certificate extended with post-quantum keys. Its first fields are exactly
// the fields of the v2 certificate it extends, so a v3 holder can always marshal that v2 form, byte for byte, and use
// it with peers that only speak v2. The v2 form keeps its own classical CA signature and fingerprint.
//
// The certificate's PQSuite says which post-quantum algorithms it uses, the way its curve does for the classical
// ones. Hosts carry a public key for the suite's KEM and CAs one for its signature algorithm. The issuing CA, which
// has the same suite, signs every field with that signature algorithm, including the suite and the classical
// signature, so neither can be swapped out. Signatures are deterministic, so a certificate extended twice is the same
// certificate.
//
// Wherever a v3 certificate deals in keys they are composite: the classical key followed by the post-quantum one.
// PublicKey returns classical || post-quantum, and VerifyPrivateKey and signing take the private keys the same way.

const (
	TagCertPQSuite     = 4 | classContextSpecific
	TagCertPQPublicKey = 5 | classContextSpecific
	TagCertPQSignature = 6 | classContextSpecific
)

// Sizes of the keys and signatures of PQSuite_MLKEM1024_MLDSA87.
const (
	// MLKEM1024PublicKeySize is the size of an ML-KEM-1024 encapsulation key.
	MLKEM1024PublicKeySize = mlkem.EncapsulationKeySize1024
	// MLKEM1024PrivateKeySize is the size of an ML-KEM-1024 decapsulation key seed.
	MLKEM1024PrivateKeySize = mlkem.SeedSize
	// MLDSA87PublicKeySize is the size of an ML-DSA-87 public key.
	MLDSA87PublicKeySize = mldsa.MLDSA87PublicKeySize
	// MLDSA87PrivateKeySize is the size of an ML-DSA-87 private key seed.
	MLDSA87PrivateKeySize = mldsa.PrivateKeySize
	// MLDSA87SignatureSize is the size of an ML-DSA-87 signature.
	MLDSA87SignatureSize = mldsa.MLDSA87SignatureSize

	// pqSignatureContext is the ML-DSA context string for certificate signatures.
	pqSignatureContext = "nebula certificate v3"
)

type certificateV3 struct {
	// v2 is the version 2 certificate this one extends. Its public key is the classical key.
	v2 certificateV2

	// pqSuite names the post-quantum algorithms, and so the kind of pqPublicKey and pqSignature.
	pqSuite PQSuite

	// pqPublicKey is the suite's KEM public key of a host, or its signature algorithm's public key of a CA.
	pqPublicKey []byte

	// pqSignature is the issuing CA's post-quantum signature over every other field.
	pqSignature []byte
}

// V2Form returns the version 2 certificate a version 3 certificate extends, or nil for any other version. It is
// what a v3 holder presents to peers that do not speak v3.
func V2Form(c Certificate) Certificate {
	if c3, ok := c.(*certificateV3); ok {
		return &c3.v2
	}
	return nil
}

func (c *certificateV3) Version() Version {
	return Version3
}

func (c *certificateV3) Curve() Curve {
	return c.v2.curve
}

func (c *certificateV3) Groups() []string {
	return c.v2.details.groups
}

func (c *certificateV3) IsCA() bool {
	return c.v2.details.isCA
}

func (c *certificateV3) Issuer() string {
	return c.v2.details.issuer
}

func (c *certificateV3) Name() string {
	return c.v2.details.name
}

func (c *certificateV3) Networks() []netip.Prefix {
	return c.v2.details.networks
}

func (c *certificateV3) NotAfter() time.Time {
	return c.v2.details.notAfter
}

func (c *certificateV3) NotBefore() time.Time {
	return c.v2.details.notBefore
}

// PublicKey returns the composite public key, classical || post-quantum.
func (c *certificateV3) PublicKey() []byte {
	k := make([]byte, 0, len(c.v2.publicKey)+len(c.pqPublicKey))
	k = append(k, c.v2.publicKey...)
	return append(k, c.pqPublicKey...)
}

func (c *certificateV3) MarshalPublicKeyPEM() []byte {
	return marshalCertPublicKeyToPEM(c)
}

// Signature returns the classical signature. The post-quantum signature covers it.
func (c *certificateV3) Signature() []byte {
	return c.v2.signature
}

func (c *certificateV3) UnsafeNetworks() []netip.Prefix {
	return c.v2.details.unsafeNetworks
}

// Fingerprint is the sha256 of the whole certificate. It differs from the fingerprint of the v2 form.
func (c *certificateV3) Fingerprint() (string, error) {
	b, err := c.Marshal()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// CheckSignature checks both signatures against the composite public key of the signing CA. Like the classical
// signature with the curve, the post-quantum signature is checked with the algorithm of this certificate's suite,
// which the signing CA has to share.
func (c *certificateV3) CheckSignature(key []byte) bool {
	p := pqSuites[c.pqSuite]
	if p == nil {
		return false
	}
	classical, pq, err := c.pqSuite.SplitPublicKey(true, key)
	if err != nil {
		return false
	}
	if !c.v2.CheckSignature(classical) {
		return false
	}
	b, err := c.marshalForPQSigning()
	if err != nil {
		return false
	}
	return p.dsa.verify(pq, b, c.pqSignature)
}

func (c *certificateV3) Expired(t time.Time) bool {
	return c.v2.Expired(t)
}

// VerifyPrivateKey checks a composite private key, classical || post-quantum seed, against the composite public key.
func (c *certificateV3) VerifyPrivateKey(curve Curve, key []byte) error {
	classical, seed, err := c.pqSuite.SplitPrivateKey(c.IsCA(), key)
	if err != nil {
		return err
	}
	if err := c.v2.VerifyPrivateKey(curve, classical); err != nil {
		return err
	}

	pub, err := c.pqSuite.publicKey(c.IsCA(), seed)
	if err != nil {
		return ErrInvalidPrivateKey
	}
	if !bytes.Equal(pub, c.pqPublicKey) {
		return ErrPublicPrivateKeyMismatch
	}
	return nil
}

func (c *certificateV3) String() string {
	mb, err := c.marshalJSON()
	if err != nil {
		return fmt.Sprintf("<error marshalling certificate: %v>", err)
	}

	b, err := json.MarshalIndent(mb, "", "\t")
	if err != nil {
		return fmt.Sprintf("<error marshalling certificate: %v>", err)
	}
	return string(b)
}

// MarshalForHandshakes leaves out both public keys, the handshake carries them as the composite static key. It keeps
// the suite, which says how to split that key.
func (c *certificateV3) MarshalForHandshakes() ([]byte, error) {
	return c.marshal(false, false)
}

func (c *certificateV3) Marshal() ([]byte, error) {
	return c.marshal(true, false)
}

// marshalForPQSigning returns the bytes the post-quantum signature covers: every field but that signature, with the
// curve always present. The suite is always present anyway.
func (c *certificateV3) marshalForPQSigning() ([]byte, error) {
	return c.marshal(true, true)
}

func (c *certificateV3) marshal(withPublicKeys, forSigning bool) ([]byte, error) {
	if c.v2.rawDetails == nil {
		return nil, ErrEmptyRawDetails
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(c.v2.rawDetails)

		if withPublicKeys {
			if forSigning || c.v2.curve != Curve_CURVE25519 {
				b.AddASN1(TagCertCurve, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte{byte(c.v2.curve)})
				})
			}
			b.AddASN1(TagCertPublicKey, func(b *cryptobyte.Builder) {
				b.AddBytes(c.v2.publicKey)
			})
		}

		b.AddASN1(TagCertSignature, func(b *cryptobyte.Builder) {
			b.AddBytes(c.v2.signature)
		})

		b.AddASN1(TagCertPQSuite, func(b *cryptobyte.Builder) {
			b.AddUint8(uint8(c.pqSuite))
		})

		if withPublicKeys {
			b.AddASN1(TagCertPQPublicKey, func(b *cryptobyte.Builder) {
				b.AddBytes(c.pqPublicKey)
			})
		}

		if !forSigning {
			b.AddASN1(TagCertPQSignature, func(b *cryptobyte.Builder) {
				b.AddBytes(c.pqSignature)
			})
		}
	})

	return b.Bytes()
}

func (c *certificateV3) MarshalPEM() ([]byte, error) {
	b, err := c.Marshal()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: CertificateV3Banner, Bytes: b}), nil
}

func (c *certificateV3) MarshalJSON() ([]byte, error) {
	b, err := c.marshalJSON()
	if err != nil {
		return nil, err
	}
	return json.Marshal(b)
}

func (c *certificateV3) marshalJSON() (m, error) {
	mb, err := c.v2.marshalJSON()
	if err != nil {
		return nil, err
	}
	fp, err := c.Fingerprint()
	if err != nil {
		return nil, err
	}

	mb["v2Fingerprint"] = mb["fingerprint"]
	mb["fingerprint"] = fp
	mb["version"] = Version3
	mb["pqSuite"] = c.pqSuite.String()
	mb["pqPublicKey"] = fmt.Sprintf("%x", c.pqPublicKey)
	mb["pqSignature"] = fmt.Sprintf("%x", c.pqSignature)
	return mb, nil
}

func (c *certificateV3) Copy() Certificate {
	nc := &certificateV3{
		v2:          *c.v2.Copy().(*certificateV2),
		pqSuite:     c.pqSuite,
		pqPublicKey: make([]byte, len(c.pqPublicKey)),
		pqSignature: make([]byte, len(c.pqSignature)),
	}
	copy(nc.pqPublicKey, c.pqPublicKey)
	copy(nc.pqSignature, c.pqSignature)
	return nc
}

func (c *certificateV3) validate() error {
	if err := c.v2.validate(); err != nil {
		return err
	}

	if !c.pqSuite.Valid() {
		return fmt.Errorf("%w: %v", ErrUnknownPQSuite, c.pqSuite)
	}
	if !c.pqSuite.checkPublicKey(c.IsCA(), c.pqPublicKey) {
		return ErrInvalidPublicKey
	}

	if len(c.pqSignature) != c.pqSuite.signatureSize() {
		return ErrBadFormat
	}
	return nil
}

// unmarshalCertificateV3 parses a v3 certificate. publicKey is the composite public key when the certificate came
// from a handshake, which then must not carry either public key itself.
func unmarshalCertificateV3(b []byte, publicKey []byte, curve Curve) (*certificateV3, error) {
	l := len(b)
	if l == 0 || l > MaxCertificateSize {
		return nil, ErrBadFormat
	}

	input := cryptobyte.String(b)
	var body cryptobyte.String
	if !input.ReadASN1(&body, asn1.SEQUENCE) || body.Empty() || !input.Empty() {
		return nil, ErrBadFormat
	}

	var rawDetails cryptobyte.String
	if !body.ReadASN1Element(&rawDetails, TagCertDetails) || rawDetails.Empty() {
		return nil, ErrBadFormat
	}

	var rawCurve byte
	if !readOptionalASN1Byte(&body, &rawCurve, TagCertCurve, byte(curve)) {
		return nil, ErrBadFormat
	}
	curve = Curve(rawCurve)

	fromHandshake := len(publicKey) > 0
	var classical, pq cryptobyte.String
	if fromHandshake {
		if body.PeekASN1Tag(TagCertPublicKey) {
			return nil, ErrCertPubkeyPresent
		}
	} else if !body.ReadASN1(&classical, TagCertPublicKey) || classical.Empty() {
		return nil, ErrBadFormat
	}

	var signature cryptobyte.String
	if !body.ReadASN1(&signature, TagCertSignature) || signature.Empty() {
		return nil, ErrBadFormat
	}

	var rawSuite cryptobyte.String
	if !body.ReadASN1(&rawSuite, TagCertPQSuite) || len(rawSuite) != 1 {
		return nil, ErrBadFormat
	}
	suite := PQSuite(rawSuite[0])
	if !suite.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrUnknownPQSuite, suite)
	}

	if fromHandshake {
		if body.PeekASN1Tag(TagCertPQPublicKey) {
			return nil, ErrCertPubkeyPresent
		}
	} else if !body.ReadASN1(&pq, TagCertPQPublicKey) || pq.Empty() {
		return nil, ErrBadFormat
	}

	var pqSignature cryptobyte.String
	if !body.ReadASN1(&pqSignature, TagCertPQSignature) || pqSignature.Empty() {
		return nil, ErrBadFormat
	}

	if !body.Empty() {
		return nil, ErrBadFormat
	}

	details, err := unmarshalDetails(rawDetails)
	if err != nil {
		return nil, err
	}

	if fromHandshake {
		k, p, err := suite.SplitPublicKey(details.isCA, publicKey)
		if err != nil {
			return nil, err
		}
		classical = bytes.Clone(k)
		pq = bytes.Clone(p)
	}

	c := &certificateV3{
		v2: certificateV2{
			details:    details,
			rawDetails: rawDetails,
			curve:      curve,
			publicKey:  classical,
			signature:  signature,
		},
		pqSuite:     suite,
		pqPublicKey: pq,
		pqSignature: pqSignature,
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	return c, nil
}

// ExtendToV3 builds the version 3 certificate in suite that extends the version 2 certificate c with pqPublicKey, the
// composite public key's post-quantum half. pqSign produces the suite's post-quantum signature, see SignPQ.
//
// A CA certificate signs its own extension: signer must be nil and pqSign must use the private key for pqPublicKey.
// A host certificate is extended by its issuing CA: signer is the v3 form of that CA, which must be in the same suite.
// In both cases c's classical signature, and so its fingerprint, are left unchanged, so certificates in use can be
// extended in place.
func ExtendToV3(c Certificate, suite PQSuite, pqPublicKey []byte, signer Certificate, pqSign SignerLambda) (Certificate, error) {
	c2, ok := c.(*certificateV2)
	if !ok {
		return nil, fmt.Errorf("only version 2 certificates can be extended to version 3, got version %d", c.Version())
	}
	if !suite.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrUnknownPQSuite, suite)
	}

	var signingKey []byte
	if c2.IsCA() {
		if signer != nil {
			return nil, fmt.Errorf("a CA certificate must extend itself, signer must be nil")
		}
		if !c2.CheckSignature(c2.publicKey) {
			return nil, ErrNotSelfSigned
		}
		signingKey = append(bytes.Clone(c2.publicKey), pqPublicKey...)
	} else {
		if signer == nil || signer.Version() != Version3 || !signer.IsCA() {
			return nil, fmt.Errorf("a host certificate must be extended by a version 3 CA")
		}
		if PQSuiteOf(signer) != suite {
			return nil, ErrPQSuiteMismatch
		}
		signerV2 := V2Form(signer)
		issuer, err := signerV2.Fingerprint()
		if err != nil {
			return nil, err
		}
		if c2.Issuer() != issuer {
			return nil, fmt.Errorf("certificate was not issued by the signing CA")
		}
		if !c2.CheckSignature(signerV2.PublicKey()) {
			return nil, ErrSignatureMismatch
		}
		signingKey = signer.PublicKey()
	}

	c3 := &certificateV3{
		v2:          *c2.Copy().(*certificateV2),
		pqSuite:     suite,
		pqPublicKey: bytes.Clone(pqPublicKey),
	}
	if len(c3.pqPublicKey) != suite.PublicKeySize(c3.IsCA()) {
		return nil, ErrInvalidPublicKey
	}

	b, err := c3.marshalForPQSigning()
	if err != nil {
		return nil, err
	}
	sig, err := pqSign(b)
	if err != nil {
		return nil, err
	}
	c3.pqSignature = sig

	if err := c3.validate(); err != nil {
		return nil, err
	}

	// Catch a pqSign that used the wrong key before the certificate goes anywhere.
	if !c3.CheckSignature(signingKey) {
		return nil, ErrSignatureMismatch
	}

	return c3, nil
}

// SignPQ returns a SignerLambda that signs certificates with the private key seed of suite's signature algorithm.
// Signatures are deterministic, so signing the same certificate twice gives the same bytes and the same fingerprint,
// and extending a certificate is idempotent.
func SignPQ(suite PQSuite, seed []byte) (SignerLambda, error) {
	p := pqSuites[suite]
	if p == nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownPQSuite, suite)
	}
	if len(seed) != p.dsa.privateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	return p.dsa.signer(seed)
}
