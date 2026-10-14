package cert

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"

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

// Version 3 keys are composite: the classical key followed by the post-quantum key, an ML-KEM-1024 seed or
// encapsulation key for hosts and an ML-DSA-87 seed or public key for CAs.
const ( //post-quantum key-agreement-key banners
	X25519MLKEM1024PrivateKeyBanner = "NEBULA X25519 MLKEM1024 PRIVATE KEY"
	X25519MLKEM1024PublicKeyBanner  = "NEBULA X25519 MLKEM1024 PUBLIC KEY"
	P256MLKEM1024PrivateKeyBanner   = "NEBULA P256 MLKEM1024 PRIVATE KEY"
	P256MLKEM1024PublicKeyBanner    = "NEBULA P256 MLKEM1024 PUBLIC KEY"
)

const ( //post-quantum signing key banners
	EncryptedECDSAP256MLDSA87PrivateKeyBanner = "NEBULA ECDSA P256 MLDSA87 ENCRYPTED PRIVATE KEY"
	ECDSAP256MLDSA87PrivateKeyBanner          = "NEBULA ECDSA P256 MLDSA87 PRIVATE KEY"
	ECDSAP256MLDSA87PublicKeyBanner           = "NEBULA ECDSA P256 MLDSA87 PUBLIC KEY"
	EncryptedEd25519MLDSA87PrivateKeyBanner   = "NEBULA ED25519 MLDSA87 ENCRYPTED PRIVATE KEY"
	Ed25519MLDSA87PrivateKeyBanner            = "NEBULA ED25519 MLDSA87 PRIVATE KEY"
	Ed25519MLDSA87PublicKeyBanner             = "NEBULA ED25519 MLDSA87 PUBLIC KEY"
)

// Classical key sizes, the composite keys of version 3 add the post-quantum key to these.
const (
	x25519KeySize          = 32
	p256PublicKeySize      = 65 // uncompressed
	p256PrivateKeySize     = 32
	ed25519PublicKeySize   = 32
	ed25519PrivateKeySize  = 64
	ecdsaP256PublicKeySize = 65 // uncompressed
)

// signingPrivateKeySize returns the size of a classical signing private key.
func signingPrivateKeySize(curve Curve) int {
	if curve == Curve_P256 {
		return p256PrivateKeySize
	}
	return ed25519PrivateKeySize
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
	if c.IsCA() {
		return MarshalSigningPublicKeyToPEM(c.Curve(), c.PublicKey())
	} else {
		return MarshalPublicKeyToPEM(c.Curve(), c.PublicKey())
	}
}

// MarshalPublicKeyToPEM returns a PEM representation of a public key used for ECDH.
// if your public key came from a certificate, prefer Certificate.PublicKeyPEM() if possible, to avoid mistakes!
func MarshalPublicKeyToPEM(curve Curve, b []byte) []byte {
	pq := len(b) > MLKEM1024PublicKeySize
	switch {
	case pq && curve == Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: X25519MLKEM1024PublicKeyBanner, Bytes: b})
	case pq && curve == Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: P256MLKEM1024PublicKeyBanner, Bytes: b})
	}
	switch curve {
	case Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: X25519PublicKeyBanner, Bytes: b})
	case Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: P256PublicKeyBanner, Bytes: b})
	default:
		return nil
	}
}

// MarshalSigningPublicKeyToPEM returns a PEM representation of a public key used for signing.
// if your public key came from a certificate, prefer Certificate.PublicKeyPEM() if possible, to avoid mistakes!
func MarshalSigningPublicKeyToPEM(curve Curve, b []byte) []byte {
	pq := len(b) > MLDSA87PublicKeySize
	switch {
	case pq && curve == Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: Ed25519MLDSA87PublicKeyBanner, Bytes: b})
	case pq && curve == Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: ECDSAP256MLDSA87PublicKeyBanner, Bytes: b})
	}
	switch curve {
	case Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: Ed25519PublicKeyBanner, Bytes: b})
	case Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: ECDSAP256PublicKeyBanner, Bytes: b})
	default:
		return nil
	}
}

// UnmarshalPublicKeyFromPEM will try to unmarshal the first pem block in a byte array, returning any non
// consumed data or an error on failure. Only key-agreement (ECDH) public key banners are accepted.
// Use UnmarshalSigningPublicKeyFromPEM for Ed25519/ECDSA banners.
func UnmarshalPublicKeyFromPEM(b []byte) ([]byte, []byte, Curve, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, 0, fmt.Errorf("input did not contain a valid PEM encoded block")
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
	case X25519MLKEM1024PublicKeyBanner:
		expectedLen = x25519KeySize + MLKEM1024PublicKeySize
		curve = Curve_CURVE25519
	case P256MLKEM1024PublicKeyBanner:
		expectedLen = p256PublicKeySize + MLKEM1024PublicKeySize
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
	case Ed25519MLDSA87PublicKeyBanner:
		expectedLen = ed25519PublicKeySize + MLDSA87PublicKeySize
		curve = Curve_CURVE25519
	case ECDSAP256MLDSA87PublicKeyBanner:
		expectedLen = ecdsaP256PublicKeySize + MLDSA87PublicKeySize
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
	pq := len(b) > MLKEM1024PrivateKeySize
	switch {
	case pq && curve == Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: X25519MLKEM1024PrivateKeyBanner, Bytes: b})
	case pq && curve == Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: P256MLKEM1024PrivateKeyBanner, Bytes: b})
	}
	switch curve {
	case Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: X25519PrivateKeyBanner, Bytes: b})
	case Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: P256PrivateKeyBanner, Bytes: b})
	default:
		return nil
	}
}

func MarshalSigningPrivateKeyToPEM(curve Curve, b []byte) []byte {
	pq := len(b) == signingPrivateKeySize(curve)+MLDSA87PrivateKeySize
	switch {
	case pq && curve == Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: Ed25519MLDSA87PrivateKeyBanner, Bytes: b})
	case pq && curve == Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: ECDSAP256MLDSA87PrivateKeyBanner, Bytes: b})
	}
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
	var expectedLen int
	var curve Curve
	switch k.Type {
	case X25519PrivateKeyBanner:
		expectedLen = 32
		curve = Curve_CURVE25519
	case P256PrivateKeyBanner:
		expectedLen = 32
		curve = Curve_P256
	case X25519MLKEM1024PrivateKeyBanner:
		expectedLen = x25519KeySize + MLKEM1024PrivateKeySize
		curve = Curve_CURVE25519
	case P256MLKEM1024PrivateKeyBanner:
		expectedLen = p256PrivateKeySize + MLKEM1024PrivateKeySize
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
	var curve Curve
	switch k.Type {
	case EncryptedEd25519PrivateKeyBanner:
		return nil, nil, Curve_CURVE25519, ErrPrivateKeyEncrypted
	case EncryptedECDSAP256PrivateKeyBanner, EncryptedECDSAP256MLDSA87PrivateKeyBanner:
		return nil, nil, Curve_P256, ErrPrivateKeyEncrypted
	case EncryptedEd25519MLDSA87PrivateKeyBanner:
		return nil, nil, Curve_CURVE25519, ErrPrivateKeyEncrypted
	case Ed25519MLDSA87PrivateKeyBanner:
		curve = Curve_CURVE25519
		if len(k.Bytes) != ed25519PrivateKeySize+MLDSA87PrivateKeySize {
			return nil, r, 0, fmt.Errorf("key was not %d bytes, is invalid Ed25519 ML-DSA-87 private key", ed25519PrivateKeySize+MLDSA87PrivateKeySize)
		}
	case ECDSAP256MLDSA87PrivateKeyBanner:
		curve = Curve_P256
		if len(k.Bytes) != p256PrivateKeySize+MLDSA87PrivateKeySize {
			return nil, r, 0, fmt.Errorf("key was not %d bytes, is invalid ECDSA P256 ML-DSA-87 private key", p256PrivateKeySize+MLDSA87PrivateKeySize)
		}
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
