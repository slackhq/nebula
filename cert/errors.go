package cert

import (
	"errors"
)

var (
	ErrBadFormat               = errors.New("bad wire format")
	ErrRootExpired             = errors.New("root certificate is expired")
	ErrExpired                 = errors.New("certificate is expired")
	ErrNotCA                   = errors.New("certificate is not a CA")
	ErrNotSelfSigned           = errors.New("certificate is not self-signed")
	ErrBlockListed             = errors.New("certificate is in the block list")
	ErrFingerprintMismatch     = errors.New("certificate fingerprint did not match")
	ErrSignatureMismatch       = errors.New("certificate signature did not match")
	ErrInvalidPublicKeyLength  = errors.New("invalid public key length")
	ErrInvalidPrivateKeyLength = errors.New("invalid private key length")

	ErrPrivateKeyEncrypted = errors.New("private key must be decrypted")

	ErrInvalidPEMBlock                   = errors.New("input did not contain a valid PEM encoded block")
	ErrInvalidPEMCertificateBanner       = errors.New("bytes did not contain a proper certificate banner")
	ErrInvalidPEMX25519PublicKeyBanner   = errors.New("bytes did not contain a proper X25519 public key banner")
	ErrInvalidPEMX25519PrivateKeyBanner  = errors.New("bytes did not contain a proper X25519 private key banner")
	ErrInvalidPEMEd25519PublicKeyBanner  = errors.New("bytes did not contain a proper Ed25519 public key banner")
	ErrInvalidPEMEd25519PrivateKeyBanner = errors.New("bytes did not contain a proper Ed25519 private key banner")
)
