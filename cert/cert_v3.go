package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert/p256"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// A version 3 certificate is a version 2 certificate's fields extended with post-quantum keys. It may carry a v2 form:
// with the v2 signature present, its first fields are exactly the fields of a v2 certificate, so a v3 holder can
// marshal that v2 form, byte for byte, and use it with peers that only speak v2. The v2 form keeps its own classical
// CA signature and fingerprint, and names its issuer by the fingerprint of the CA's v2 form. Without the v2 signature
// there is no v2 form, and the details name no issuer either: the certificate is for v3 peers only. Either way the
// v3 certificate names its issuer by the v3 CA's own fingerprint, so it is bound to that CA's keys and not just to a
// v2 CA. Whether a certificate has a v2 form is the CA's choice, covered by its signatures: a v2 form can not be
// stripped, and a CA without one can not issue one.
//
// The certificate's PQSuite says which post-quantum algorithms it uses, the way its curve does for the classical
// ones. Hosts carry a public key for the suite's KEM and CAs one for its signature algorithm. The issuing CA, which
// has the same suite and curve, signs every field twice, once with each of its keys, as a composite signature: both
// signatures sign the same message, see signedMessage, and both must verify, so the certificate stays sound while
// either algorithm does. A CA's extension is signed by both of its own keys, so only the holder of the classical CA
// key can extend a CA. Signatures are deterministic, so a certificate extended twice is the same certificate.
//
// Wherever a v3 certificate deals in keys they are composite: the classical key followed by the post-quantum one.
// PublicKey returns classical || post-quantum, and VerifyPrivateKey and signing take the private keys the same way.

const (
	TagCertPQSuite            = 4 | classContextSpecific
	TagCertPQIssuer           = 5 | classContextSpecific
	TagCertPQPublicKey        = 6 | classContextSpecific
	TagCertClassicalSignature = 7 | classContextSpecific
	TagCertPQSignature        = 8 | classContextSpecific
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
)

const (
	// compositeSignaturePrefix starts every message a version 3 certificate's signatures sign. It is the Prefix of
	// draft-ietf-lamps-pq-composite-sigs, whose construction those signatures follow.
	compositeSignaturePrefix = "CompositeAlgorithmSignatures2025"

	// signatureContext is the ctx of that construction, naming what is signed.
	signatureContext = "nebula certificate v3"
)

type certificateV3 struct {
	// v2 holds the version 2 fields of this certificate, its public key the classical key. With a signature it is the
	// v2 form; without one, it is not a certificate on its own and its details name no issuer.
	v2 certificateV2

	// pqSuite names the post-quantum algorithms, and so the kind of pqPublicKey and pqSignature.
	pqSuite PQSuite

	// issuer is the fingerprint of the v3 CA that signed this certificate, empty for a CA.
	issuer string

	// pqPublicKey is the suite's KEM public key of a host, or its signature algorithm's public key of a CA.
	pqPublicKey []byte

	// classicalSignature is the issuing CA's classical signature of messagePrime, unlike the classical signature of
	// the v2 form, which covers only the fields of that.
	classicalSignature []byte

	// pqSignature is the issuing CA's post-quantum signature of messagePrime.
	pqSignature []byte
}

// V2Form returns the version 2 form of a version 3 certificate, or nil for one without a v2 form and for any other
// version. It is what a v3 holder presents to peers that do not speak v3.
func V2Form(c Certificate) Certificate {
	if c3, ok := c.(*certificateV3); ok && c3.hasV2Form() {
		return &c3.v2
	}
	return nil
}

// hasV2Form reports whether the certificate carries a v2 form, which its v2 signature makes it.
func (c *certificateV3) hasV2Form() bool {
	return len(c.v2.signature) > 0
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

// Issuer is the fingerprint of the v3 CA that signed this certificate. The v2 form names the CA's v2 form instead.
func (c *certificateV3) Issuer() string {
	return c.issuer
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

// Signature returns the two signatures of the whole certificate. The v2 form's own signature is that of V2Form.
func (c *certificateV3) Signature() Signatures {
	return Signatures{Classical: c.classicalSignature, PQ: c.pqSignature}
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

// CheckSignature checks every signature against the composite public key of the signing CA: the v2 form's, when there
// is one, and both signatures of the whole certificate. They are checked with the algorithms of this certificate's curve and suite,
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
	//if the cert has a v2 form available, verify it first
	if c.hasV2Form() && !c.v2.CheckSignature(classical) {
		return false
	}

	//next, verify the pq-hybrid form of the cert:
	m, err := c.messagePrime()
	if err != nil {
		return false
	}
	return verifyClassical(c.v2.curve, classical, m, c.classicalSignature) &&
		p.dsa.verify(pq, m, c.pqSignature, c.pqSuite.SignatureLabel(c.v2.curve))
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

// messagePrime returns the message both signatures of the whole certificate sign, M' of draft-ietf-lamps-pq-composite-
// sigs: Prefix || Label || len(ctx) || ctx || SHA-512(M), where M is every field but those two signatures, with the
// curve always present, Label is the suite's SignatureLabel for the curve and ctx is signatureContext.
//
// The classical CA key also signs v2 certificates, the v2 form of this one among them, and v1 ones, which
// draft-ietf-lamps-pq-composite-sigs forbids (§3.1, §9.3). Every message signed here starts with the prefix, which no
// v1 or v2 signing input does, so neither signature can be taken for a signature of anything else the key signs.
func (c *certificateV3) messagePrime() ([]byte, error) {
	label := c.pqSuite.SignatureLabel(c.v2.curve)
	if label == "" {
		return nil, fmt.Errorf("%w: %v with curve %v", ErrUnknownPQSuite, c.pqSuite, c.v2.curve)
	}
	b, err := c.marshal(true, true)
	if err != nil {
		return nil, err
	}
	sum := sha512.Sum512(b)
	m := make([]byte, 0, len(compositeSignaturePrefix)+len(label)+1+len(signatureContext)+len(sum))
	m = append(m, compositeSignaturePrefix...)
	m = append(m, label...)
	m = append(m, byte(len(signatureContext)))
	m = append(m, signatureContext...)
	return append(m, sum[:]...), nil
}

// verifyClassical checks a classical signature of m. A P256 signature must be in its low-s form: nothing else covers
// it, and the high-s form would give the certificate a second encoding and fingerprint.
func verifyClassical(curve Curve, key, m, sig []byte) bool {
	switch curve {
	case Curve_CURVE25519:
		return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, m, sig)
	case Curve_P256:
		if low, err := p256.IsNormalized(sig); err != nil || !low {
			return false
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), key)
		if err != nil {
			return false
		}
		hashed := sha256.Sum256(m)
		return ecdsa.VerifyASN1(pub, hashed[:], sig)
	default:
		return false
	}
}

func (c *certificateV3) marshal(withPublicKeys, forSigning bool) ([]byte, error) {
	if c.v2.rawDetails == nil {
		return nil, ErrEmptyRawDetails
	}
	issuer, err := hex.DecodeString(c.issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to decode issuer: %w", err)
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

		if c.hasV2Form() {
			b.AddASN1(TagCertSignature, func(b *cryptobyte.Builder) {
				b.AddBytes(c.v2.signature)
			})
		}

		b.AddASN1(TagCertPQSuite, func(b *cryptobyte.Builder) {
			b.AddUint8(uint8(c.pqSuite))
		})

		if len(issuer) > 0 {
			b.AddASN1(TagCertPQIssuer, func(b *cryptobyte.Builder) {
				b.AddBytes(issuer)
			})
		}

		if withPublicKeys {
			b.AddASN1(TagCertPQPublicKey, func(b *cryptobyte.Builder) {
				b.AddBytes(c.pqPublicKey)
			})
		}

		if !forSigning {
			b.AddASN1(TagCertClassicalSignature, func(b *cryptobyte.Builder) {
				b.AddBytes(c.classicalSignature)
			})
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

	if c.hasV2Form() {
		mb["v2Fingerprint"] = mb["fingerprint"]
		mb["v2Issuer"] = mb["issuer"]
		mb["v2Signature"] = mb["signature"]
	}
	mb["fingerprint"] = fp
	mb["issuer"] = c.issuer
	mb["signature"] = fmt.Sprintf("%x", c.classicalSignature)
	mb["version"] = Version3
	mb["pqSuite"] = c.pqSuite.String()
	mb["pqPublicKey"] = fmt.Sprintf("%x", c.pqPublicKey)
	mb["pqSignature"] = fmt.Sprintf("%x", c.pqSignature)
	return mb, nil
}

func (c *certificateV3) Copy() Certificate {
	nc := &certificateV3{
		v2:                 *c.v2.Copy().(*certificateV2),
		pqSuite:            c.pqSuite,
		issuer:             c.issuer,
		pqPublicKey:        make([]byte, len(c.pqPublicKey)),
		classicalSignature: bytes.Clone(c.classicalSignature),
		pqSignature:        make([]byte, len(c.pqSignature)),
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
	// Without the suite's algorithms no key can be checked, and the reason is worth more than invalid public key.
	if err := c.pqSuite.Available(); err != nil {
		return err
	}
	if !c.pqSuite.checkPublicKey(c.IsCA(), c.pqPublicKey) {
		return ErrInvalidPublicKey
	}

	// A CA signs itself, everything else names the CA that signed it.
	if c.IsCA() != (c.issuer == "") || (c.issuer != "" && len(c.issuer) != 2*sha256.Size) {
		return ErrBadFormat
	}

	// The details name the issuer of the v2 form, so they name one exactly when a host certificate has a v2 form.
	v2Issuer := c.v2.details.issuer
	if (v2Issuer != "") != (c.hasV2Form() && !c.IsCA()) || (v2Issuer != "" && len(v2Issuer) != 2*sha256.Size) {
		return ErrBadFormat
	}

	if len(c.pqSignature) != c.pqSuite.signatureSize() {
		return ErrBadFormat
	}

	switch c.v2.curve {
	case Curve_CURVE25519:
		if len(c.classicalSignature) != ed25519.SignatureSize {
			return ErrBadFormat
		}
	case Curve_P256:
		if low, err := p256.IsNormalized(c.classicalSignature); err != nil || !low {
			return ErrBadFormat
		}
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

	// The v2 signature is there only with a v2 form.
	var signature cryptobyte.String
	if body.PeekASN1Tag(TagCertSignature) && (!body.ReadASN1(&signature, TagCertSignature) || signature.Empty()) {
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

	var issuer cryptobyte.String
	if body.PeekASN1Tag(TagCertPQIssuer) && (!body.ReadASN1(&issuer, TagCertPQIssuer) || issuer.Empty()) {
		return nil, ErrBadFormat
	}

	if fromHandshake {
		if body.PeekASN1Tag(TagCertPQPublicKey) {
			return nil, ErrCertPubkeyPresent
		}
	} else if !body.ReadASN1(&pq, TagCertPQPublicKey) || pq.Empty() {
		return nil, ErrBadFormat
	}

	var classicalSignature cryptobyte.String
	if !body.ReadASN1(&classicalSignature, TagCertClassicalSignature) || classicalSignature.Empty() {
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
		pqSuite:            suite,
		issuer:             hex.EncodeToString(issuer),
		pqPublicKey:        pq,
		classicalSignature: classicalSignature,
		pqSignature:        pqSignature,
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	return c, nil
}

// ExtendToV3 builds the version 3 certificate in suite that extends the version 2 certificate c with pqPublicKey, the
// composite public key's post-quantum half. sign and pqSign produce the two signatures of the whole certificate, with
// the classical and post-quantum halves of the signing composite key, see SignClassical and SignPQ.
//
// A CA certificate signs its own extension: signer must be nil, sign must use the CA's classical key and pqSign the
// private key for pqPublicKey. A host certificate is extended by its issuing CA: signer is the v3 form of that CA,
// which must be in the same suite, and becomes the v3 certificate's issuer. In both cases c's classical signature,
// and so its fingerprint, are left unchanged, so certificates in use can be extended in place.
func ExtendToV3(c Certificate, suite PQSuite, pqPublicKey []byte, signer Certificate, sign, pqSign SignerLambda) (Certificate, error) {
	c2, ok := c.(*certificateV2)
	if !ok {
		return nil, fmt.Errorf("only version 2 certificates can be extended to version 3, got version %d", c.Version())
	}
	if !suite.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrUnknownPQSuite, suite)
	}

	var signingKey []byte
	var v3Issuer string
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
		if signerV2 == nil {
			return nil, ErrNoV2FormCA
		}
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
		if v3Issuer, err = signer.Fingerprint(); err != nil {
			return nil, err
		}
	}

	c3 := &certificateV3{
		v2:          *c2.Copy().(*certificateV2),
		pqSuite:     suite,
		issuer:      v3Issuer,
		pqPublicKey: bytes.Clone(pqPublicKey),
	}
	return c3.sign(signingKey, sign, pqSign)
}

// sign makes both signatures of the whole certificate, then checks every signature against signingKey, the composite
// public key of the signing CA, so a signer that used the wrong key is caught before the certificate goes anywhere.
func (c3 *certificateV3) sign(signingKey []byte, sign, pqSign SignerLambda) (Certificate, error) {
	if len(c3.pqPublicKey) != c3.pqSuite.PublicKeySize(c3.IsCA()) {
		return nil, ErrInvalidPublicKey
	}

	m, err := c3.messagePrime()
	if err != nil {
		return nil, err
	}
	if c3.classicalSignature, err = sign(m); err != nil {
		return nil, err
	}
	if c3.v2.curve == Curve_P256 {
		if c3.classicalSignature, err = p256.Normalize(c3.classicalSignature); err != nil {
			return nil, err
		}
	}
	if c3.pqSignature, err = pqSign(m); err != nil {
		return nil, err
	}

	if err := c3.validate(); err != nil {
		return nil, err
	}

	// A v2 certificate near the limit grows past it when extended, and a parser would refuse the result.
	b, err := c3.Marshal()
	if err != nil {
		return nil, err
	}
	if len(b) > MaxCertificateSize {
		return nil, fmt.Errorf("%w: the version 3 certificate would be %d bytes, over the %d byte maximum", ErrBadFormat, len(b), MaxCertificateSize)
	}

	if !c3.CheckSignature(signingKey) {
		return nil, ErrSignatureMismatch
	}

	return c3, nil
}

// SignPQ returns a SignerLambda that signs version 3 certificates of suite and curve with the private key seed of the
// suite's signature algorithm, its context the suite's SignatureLabel for the curve. Signatures are deterministic, so
// signing the same certificate twice gives the same bytes and the same fingerprint, and extending a certificate with
// the same keys is idempotent.
func SignPQ(suite PQSuite, curve Curve, seed []byte) (SignerLambda, error) {
	p := pqSuites[suite]
	if p == nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownPQSuite, suite)
	}
	label := suite.SignatureLabel(curve)
	if label == "" {
		return nil, fmt.Errorf("invalid curve: %s", curve)
	}
	if len(seed) != p.dsa.privateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	return p.dsa.signer(seed, label)
}

// SignClassical returns a SignerLambda that signs version 3 certificates with a classical CA private key of curve.
// Signatures are deterministic, Ed25519 by design and ECDSA P256 per RFC 6979, for the same reason as SignPQ's.
func SignClassical(curve Curve, key []byte) (SignerLambda, error) {
	switch curve {
	case Curve_CURVE25519:
		if len(key) != ed25519.PrivateKeySize {
			return nil, ErrInvalidPrivateKey
		}
		pk := ed25519.PrivateKey(key)
		return func(m []byte) ([]byte, error) {
			return ed25519.Sign(pk, m), nil
		}, nil
	case Curve_P256:
		pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
		if err != nil {
			return nil, err
		}
		return func(m []byte) ([]byte, error) {
			hashed := sha256.Sum256(m)
			return pk.Sign(nil, hashed[:], crypto.SHA256)
		}, nil
	default:
		return nil, fmt.Errorf("invalid curve: %s", curve)
	}
}
