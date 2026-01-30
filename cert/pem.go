package cert

import (
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

const ( //cert banners
	CertificateBanner   = "NEBULA CERTIFICATE"
	CertificateV2Banner = "NEBULA CERTIFICATE V2"
)

const ( //key-agreement-key banners
	X25519PrivateKeyBanner = "NEBULA X25519 PRIVATE KEY"
	X25519PublicKeyBanner  = "NEBULA X25519 PUBLIC KEY"
	P256PrivateKeyBanner   = "NEBULA P256 PRIVATE KEY"
	P256PublicKeyBanner    = "NEBULA P256 PUBLIC KEY"
)

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

	var c Certificate
	var err error

	switch p.Type {
	// Implementations must validate the resulting certificate contains valid information
	case CertificateBanner:
		c, err = unmarshalCertificateV1(p.Bytes, nil)
	case CertificateV2Banner:
		c, err = unmarshalCertificateV2(p.Bytes, nil, Curve_CURVE25519)
	default:
		return nil, r, ErrInvalidPEMCertificateBanner
	}

	if err != nil {
		return nil, r, err
	}

	return c, r, nil

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
	switch curve {
	case Curve_CURVE25519:
		return pem.EncodeToMemory(&pem.Block{Type: Ed25519PublicKeyBanner, Bytes: b})
	case Curve_P256:
		return pem.EncodeToMemory(&pem.Block{Type: ECDSAP256PublicKeyBanner, Bytes: b})
	default:
		return nil
	}
}

func UnmarshalPublicKeyFromPEM(b []byte) ([]byte, []byte, Curve, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, 0, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	var expectedLen int
	var curve Curve
	switch k.Type {
	case X25519PublicKeyBanner, Ed25519PublicKeyBanner:
		expectedLen = 32
		curve = Curve_CURVE25519
	case P256PublicKeyBanner, ECDSAP256PublicKeyBanner:
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
