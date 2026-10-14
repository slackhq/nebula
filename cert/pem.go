package cert

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ed25519"
)

var ErrTruncatedPEMBlock = errors.New("truncated PEM block")

// SplitPEM is a split function for bufio.Scanner that returns each PEM block.
func SplitPEM(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Look for the start of a PEM block
	start := bytes.Index(data, []byte("-----BEGIN "))
	if start == -1 {
		if atEOF && len(bytes.TrimSpace(data)) > 0 {
			// Non-whitespace content with no PEM block
			return 0, nil, ErrTruncatedPEMBlock
		}
		if atEOF {
			return len(data), nil, nil
		}
		// Request more data
		return 0, nil, nil
	}

	// Look for the end marker
	endMarkerStart := bytes.Index(data[start:], []byte("-----END "))
	if endMarkerStart == -1 {
		if atEOF {
			// Incomplete PEM block at EOF
			return 0, nil, ErrTruncatedPEMBlock
		}
		// Need more data to find the end
		return 0, nil, nil
	}

	// Find the actual end of the END line (after the newline)
	endMarkerStart += start
	endLineEnd := bytes.IndexByte(data[endMarkerStart:], '\n')
	var end int
	if endLineEnd == -1 {
		if atEOF {
			// END marker without newline at EOF - take it anyway
			end = len(data)
		} else {
			// Need more data
			return 0, nil, nil
		}
	} else {
		end = endMarkerStart + endLineEnd + 1
	}

	// Extract the PEM block
	pemBlock := data[start:end]

	// Return the valid PEM block
	return end, pemBlock, nil
}

const ( //cert banners
	CertificateBanner   = "NEBULA CERTIFICATE"
	CertificateV2Banner = "NEBULA CERTIFICATE V2"
	CertificateV3Banner = "NEBULA CERTIFICATE V3"
)

const ( //key-agreement-key banners
	X25519PrivateKeyBanner = "NEBULA X25519 PRIVATE KEY"
	X25519PublicKeyBanner  = "NEBULA X25519 PUBLIC KEY"
	P256PrivateKeyBanner   = "NEBULA P256 PRIVATE KEY"
	P256PublicKeyBanner    = "NEBULA P256 PUBLIC KEY"
)

// Version 3 keys are composite: the classical key followed by the post-quantum key of the certificate's PQSuite, a
// KEM seed or public key for hosts and a signature algorithm's seed or public key for CAs. Their banners name both
// halves, "NEBULA X25519 MLKEM1024 PRIVATE KEY" or "NEBULA ED25519 MLDSA87 PUBLIC KEY" for example, because the
// post-quantum algorithm can not be told from the key's size: ML-KEM and ML-DSA seeds are the same size at every
// strength. The banners name algorithms, not suites, so suites sharing an algorithm share its banners too.

// Classical key sizes, the composite keys of version 3 add the post-quantum key to these.
const (
	x25519KeySize          = 32
	p256PublicKeySize      = 65 // uncompressed
	p256PrivateKeySize     = 32
	ed25519PublicKeySize   = 32
	ed25519PrivateKeySize  = 64
	ecdsaP256PublicKeySize = 65 // uncompressed
)

// ClassicalPrivateKey returns the classical half of a host private key: all of a classical key, or the classical half
// of a composite one, whatever its suite.
func ClassicalPrivateKey(key []byte) []byte {
	// X25519 and P256 private keys are the same size.
	if len(key) > x25519KeySize {
		return key[:x25519KeySize]
	}
	return key
}

// pqKeyKind is what a composite key banner holds.
type pqKeyKind int

const (
	pqPrivateKey pqKeyKind = iota
	pqPublicKey
	pqSigningPrivateKey
	pqSigningPublicKey
	pqEncryptedSigningPrivateKey
)

// pqKeyBanner is what a composite key banner says about the key under it.
type pqKeyBanner struct {
	kind  pqKeyKind
	curve Curve
	size  int // of the whole composite key; for an encrypted key, once decrypted
}

var pqKeyKinds = []pqKeyKind{pqPrivateKey, pqPublicKey, pqSigningPrivateKey, pqSigningPublicKey, pqEncryptedSigningPrivateKey}

// pqKeyBanners maps every composite key banner of every suite to what it holds, see registerPQSuite.
var pqKeyBanners = map[string]pqKeyBanner{}

// pqBannerName returns the banner for a composite key.
func pqBannerName(kind pqKeyKind, curve Curve, suite *pqSuite) string {
	classical := map[Curve]string{Curve_CURVE25519: "X25519", Curve_P256: "P256"}[curve]
	alg := suite.kem.name
	if kind != pqPrivateKey && kind != pqPublicKey {
		classical = map[Curve]string{Curve_CURVE25519: "ED25519", Curve_P256: "ECDSA P256"}[curve]
		alg = suite.dsa.name
	}
	return "NEBULA " + classical + " " + alg + " " + map[pqKeyKind]string{
		pqPrivateKey:                 "PRIVATE KEY",
		pqPublicKey:                  "PUBLIC KEY",
		pqSigningPrivateKey:          "PRIVATE KEY",
		pqSigningPublicKey:           "PUBLIC KEY",
		pqEncryptedSigningPrivateKey: "ENCRYPTED PRIVATE KEY",
	}[kind]
}

// pqKeySize returns the size of a composite key.
func pqKeySize(kind pqKeyKind, curve Curve, suite *pqSuite) int {
	p256 := curve == Curve_P256
	switch kind {
	case pqPrivateKey:
		return x25519KeySize + suite.kem.privateKeySize // a P256 private key is the same size
	case pqPublicKey:
		return map[bool]int{false: x25519KeySize, true: p256PublicKeySize}[p256] + suite.kem.publicKeySize
	case pqSigningPublicKey:
		return map[bool]int{false: ed25519PublicKeySize, true: ecdsaP256PublicKeySize}[p256] + suite.dsa.publicKeySize
	default:
		return map[bool]int{false: ed25519PrivateKeySize, true: p256PrivateKeySize}[p256] + suite.dsa.privateKeySize
	}
}

// marshalPQKeyToPEM PEM encodes a composite key of suite, nil for an unknown curve or suite or a key of the wrong size.
func marshalPQKeyToPEM(kind pqKeyKind, curve Curve, suite PQSuite, b []byte) []byte {
	p := pqSuites[suite]
	if p == nil || (curve != Curve_CURVE25519 && curve != Curve_P256) || len(b) != pqKeySize(kind, curve, p) {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: pqBannerName(kind, curve, p), Bytes: b})
}

// unmarshalPQKeyBlock checks a PEM block that may hold a composite key of one of kinds. ok is false when the banner
// is not a composite key banner of those kinds at all.
func unmarshalPQKeyBlock(k *pem.Block, kinds ...pqKeyKind) (curve Curve, ok bool, err error) {
	b, found := pqKeyBanners[k.Type]
	if !found || !slices.Contains(kinds, b.kind) {
		return 0, false, nil
	}
	if b.kind != pqEncryptedSigningPrivateKey && len(k.Bytes) != b.size {
		return b.curve, true, fmt.Errorf("key was not %d bytes, is invalid %s", b.size, strings.ToLower(strings.TrimPrefix(k.Type, "NEBULA ")))
	}
	return b.curve, true, nil
}

/* including "ECDSA" in the P256 banners is a clue that these keys should be used only for signing */
const ( //signing key banners
	EncryptedECDSAP256PrivateKeyBanner = "NEBULA ECDSA P256 ENCRYPTED PRIVATE KEY"
	ECDSAP256PrivateKeyBanner          = "NEBULA ECDSA P256 PRIVATE KEY"
	ECDSAP256PublicKeyBanner           = "NEBULA ECDSA P256 PUBLIC KEY"
	EncryptedEd25519PrivateKeyBanner   = "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
	Ed25519PrivateKeyBanner            = "NEBULA ED25519 PRIVATE KEY"
	Ed25519PublicKeyBanner             = "NEBULA ED25519 PUBLIC KEY"
)

// UnmarshalCertificateFromPEM will try to unmarshal the first pem block in a byte array, returning any non consumed
// data or an error on failure
func UnmarshalCertificateFromPEM(b []byte) (Certificate, []byte, error) {
	p, r := pem.Decode(b)
	if p == nil {
		return nil, r, ErrInvalidPEMBlock
	}

	c, err := unmarshalCertificateBlock(p)
	if err != nil {
		return nil, r, err
	}

	return c, r, nil

}

// unmarshalCertificateBlock decodes a single PEM block into a certificate.
// It expects a Nebula certificate banner and returns ErrInvalidPEMCertificateBanner otherwise.
func unmarshalCertificateBlock(block *pem.Block) (Certificate, error) {
	switch block.Type {
	// Implementations must validate the resulting certificate contains valid information
	case CertificateBanner:
		return unmarshalCertificateV1(block.Bytes, nil)
	case CertificateV2Banner:
		return unmarshalCertificateV2(block.Bytes, nil, Curve_CURVE25519)
	case CertificateV3Banner:
		return unmarshalCertificateV3(block.Bytes, nil, Curve_CURVE25519)
	default:
		return nil, ErrInvalidPEMCertificateBanner
	}
}

func marshalCertPublicKeyToPEM(c Certificate) []byte {
	if suite := PQSuiteOf(c); suite != PQSuiteUnknown {
		if c.IsCA() {
			return MarshalPQSigningPublicKeyToPEM(c.Curve(), suite, c.PublicKey())
		}
		return MarshalPQPublicKeyToPEM(c.Curve(), suite, c.PublicKey())
	}
	if c.IsCA() {
		return MarshalSigningPublicKeyToPEM(c.Curve(), c.PublicKey())
	} else {
		return MarshalPublicKeyToPEM(c.Curve(), c.PublicKey())
	}
}

// MarshalPublicKeyToPEM returns a PEM representation of a public key used for ECDH.
// if your public key came from a certificate, prefer Certificate.PublicKeyPEM() if possible, to avoid mistakes!
func MarshalPublicKeyToPEM(curve Curve, b []byte) []byte {
	switch curve {
	case Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: X25519PublicKeyBanner, Bytes: b})
	case Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: P256PublicKeyBanner, Bytes: b})
	default:
		return nil
	}
}

// MarshalPQPublicKeyToPEM returns a PEM representation of a composite host public key of suite, the classical ECDH
// key followed by the suite's KEM public key, or nil if b is not one.
func MarshalPQPublicKeyToPEM(curve Curve, suite PQSuite, b []byte) []byte {
	return marshalPQKeyToPEM(pqPublicKey, curve, suite, b)
}

// MarshalSigningPublicKeyToPEM returns a PEM representation of a public key used for signing.
// if your public key came from a certificate, prefer Certificate.PublicKeyPEM() if possible, to avoid mistakes!
func MarshalSigningPublicKeyToPEM(curve Curve, b []byte) []byte {
	switch curve {
	case Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: Ed25519PublicKeyBanner, Bytes: b})
	case Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: ECDSAP256PublicKeyBanner, Bytes: b})
	default:
		return nil
	}
}

// MarshalPQSigningPublicKeyToPEM returns a PEM representation of a composite CA public key of suite, the classical
// signing key followed by the public key of the suite's signature algorithm, or nil if b is not one.
func MarshalPQSigningPublicKeyToPEM(curve Curve, suite PQSuite, b []byte) []byte {
	return marshalPQKeyToPEM(pqSigningPublicKey, curve, suite, b)
}

// UnmarshalPublicKeyFromPEM will try to unmarshal the first pem block in a byte array, returning any non
// consumed data or an error on failure. Only key-agreement (ECDH) public key banners are accepted.
// Use UnmarshalSigningPublicKeyFromPEM for Ed25519/ECDSA banners.
func UnmarshalPublicKeyFromPEM(b []byte) ([]byte, []byte, Curve, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, 0, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if curve, ok, err := unmarshalPQKeyBlock(k, pqPublicKey); ok {
		if err != nil {
			return nil, r, 0, err
		}
		return k.Bytes, r, curve, nil
	}
	var expectedLen int
	var curve Curve
	switch k.Type {
	case X25519PublicKeyBanner:
		expectedLen = 32
		curve = Curve_CURVE25519
	case P256PublicKeyBanner:
		// Uncompressed
		expectedLen = 65
		curve = Curve_P256
	default:
		return nil, r, 0, fmt.Errorf("bytes did not contain a proper public key banner")
	}
	if len(k.Bytes) != expectedLen {
		return nil, r, 0, fmt.Errorf("key was not %d bytes, is invalid %s public key", expectedLen, curve)
	}
	return k.Bytes, r, curve, nil
}

// UnmarshalSigningPublicKeyFromPEM will try to unmarshal the first pem block in a byte array, returning any non
// consumed data or an error on failure. Only Ed25519/ECDSA public key banners are accepted.
// Use UnmarshalPublicKeyFromPEM for X25519/P256 (ECDH) banners.
func UnmarshalSigningPublicKeyFromPEM(b []byte) ([]byte, []byte, Curve, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, 0, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if curve, ok, err := unmarshalPQKeyBlock(k, pqSigningPublicKey); ok {
		if err != nil {
			return nil, r, 0, err
		}
		return k.Bytes, r, curve, nil
	}
	var expectedLen int
	var curve Curve
	switch k.Type {
	case Ed25519PublicKeyBanner:
		expectedLen = 32
		curve = Curve_CURVE25519
	case ECDSAP256PublicKeyBanner:
		// Uncompressed
		expectedLen = 65
		curve = Curve_P256
	default:
		return nil, r, 0, fmt.Errorf("bytes did not contain a proper Ed25519/ECDSA public key banner")
	}
	if len(k.Bytes) != expectedLen {
		return nil, r, 0, fmt.Errorf("key was not %d bytes, is invalid %s public key", expectedLen, curve)
	}
	return k.Bytes, r, curve, nil
}

func MarshalPrivateKeyToPEM(curve Curve, b []byte) []byte {
	switch curve {
	case Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: X25519PrivateKeyBanner, Bytes: b})
	case Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: P256PrivateKeyBanner, Bytes: b})
	default:
		return nil
	}
}

// MarshalPQPrivateKeyToPEM returns a PEM representation of a composite host private key of suite, the classical ECDH
// key followed by the seed of the suite's KEM, or nil if b is not one.
func MarshalPQPrivateKeyToPEM(curve Curve, suite PQSuite, b []byte) []byte {
	return marshalPQKeyToPEM(pqPrivateKey, curve, suite, b)
}

// MarshalPQSigningPrivateKeyToPEM returns a PEM representation of a composite CA private key of suite, the classical
// signing key followed by the seed of the suite's signature algorithm, or nil if b is not one.
func MarshalPQSigningPrivateKeyToPEM(curve Curve, suite PQSuite, b []byte) []byte {
	return marshalPQKeyToPEM(pqSigningPrivateKey, curve, suite, b)
}

func MarshalSigningPrivateKeyToPEM(curve Curve, b []byte) []byte {
	switch curve {
	case Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: Ed25519PrivateKeyBanner, Bytes: b})
	case Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: ECDSAP256PrivateKeyBanner, Bytes: b})
	default:
		return nil
	}
}

// UnmarshalPrivateKeyFromPEM will try to unmarshal the first pem block in a byte array, returning any non
// consumed data or an error on failure
func UnmarshalPrivateKeyFromPEM(b []byte) ([]byte, []byte, Curve, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, 0, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if curve, ok, err := unmarshalPQKeyBlock(k, pqPrivateKey); ok {
		if err != nil {
			return nil, r, 0, err
		}
		return k.Bytes, r, curve, nil
	}
	var expectedLen int
	var curve Curve
	switch k.Type {
	case X25519PrivateKeyBanner:
		expectedLen = 32
		curve = Curve_CURVE25519
	case P256PrivateKeyBanner:
		expectedLen = 32
		curve = Curve_P256
	default:
		return nil, r, 0, fmt.Errorf("bytes did not contain a proper private key banner")
	}
	if len(k.Bytes) != expectedLen {
		return nil, r, 0, fmt.Errorf("key was not %d bytes, is invalid %s private key", expectedLen, curve)
	}
	return k.Bytes, r, curve, nil
}

func UnmarshalSigningPrivateKeyFromPEM(b []byte) ([]byte, []byte, Curve, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, 0, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if curve, ok, err := unmarshalPQKeyBlock(k, pqSigningPrivateKey, pqEncryptedSigningPrivateKey); ok {
		switch {
		case err != nil:
			return nil, r, 0, err
		case pqKeyBanners[k.Type].kind == pqEncryptedSigningPrivateKey:
			return nil, nil, curve, ErrPrivateKeyEncrypted
		}
		return k.Bytes, r, curve, nil
	}
	var curve Curve
	switch k.Type {
	case EncryptedEd25519PrivateKeyBanner:
		return nil, nil, Curve_CURVE25519, ErrPrivateKeyEncrypted
	case EncryptedECDSAP256PrivateKeyBanner:
		return nil, nil, Curve_P256, ErrPrivateKeyEncrypted
	case Ed25519PrivateKeyBanner:
		curve = Curve_CURVE25519
		if len(k.Bytes) != ed25519.PrivateKeySize {
			return nil, r, 0, fmt.Errorf("key was not %d bytes, is invalid Ed25519 private key", ed25519.PrivateKeySize)
		}
	case ECDSAP256PrivateKeyBanner:
		curve = Curve_P256
		if len(k.Bytes) != 32 {
			return nil, r, 0, fmt.Errorf("key was not 32 bytes, is invalid ECDSA P256 private key")
		}
	default:
		return nil, r, 0, fmt.Errorf("bytes did not contain a proper Ed25519/ECDSA private key banner")
	}
	return k.Bytes, r, curve, nil
}
