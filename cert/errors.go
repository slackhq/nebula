package cert

import (
	"errors"
	"fmt"
)

var (
	ErrBadFormat                  = errors.New("bad wire format")
	ErrRootExpired                = errors.New("root certificate is expired")
	ErrExpired                    = errors.New("certificate is expired")
	ErrNotCA                      = errors.New("certificate is not a CA")
	ErrNotSelfSigned              = errors.New("certificate is not self-signed")
	ErrBlockListed                = errors.New("certificate is in the block list")
	ErrFingerprintMismatch        = errors.New("certificate fingerprint did not match")
	ErrSignatureMismatch          = errors.New("certificate signature did not match")
	ErrInvalidPublicKey           = errors.New("invalid public key")
	ErrInvalidPrivateKey          = errors.New("invalid private key")
	ErrPublicPrivateCurveMismatch = errors.New("public key does not match private key curve")
	ErrPublicPrivateKeyMismatch   = errors.New("public key and private key are not a pair")
	ErrPrivateKeyEncrypted        = errors.New("private key must be decrypted")
	ErrCaNotFound                 = errors.New("could not find ca for the certificate")
	ErrUnknownVersion             = errors.New("certificate version unrecognized")
	ErrCertPubkeyPresent          = errors.New("certificate has unexpected pubkey present")

	ErrInvalidPEMBlock                   = errors.New("input did not contain a valid PEM encoded block")
	ErrInvalidPEMCertificateBanner       = errors.New("bytes did not contain a proper certificate banner")
	ErrInvalidPEMX25519PublicKeyBanner   = errors.New("bytes did not contain a proper X25519 public key banner")
	ErrInvalidPEMX25519PrivateKeyBanner  = errors.New("bytes did not contain a proper X25519 private key banner")
	ErrInvalidPEMEd25519PublicKeyBanner  = errors.New("bytes did not contain a proper Ed25519 public key banner")
	ErrInvalidPEMEd25519PrivateKeyBanner = errors.New("bytes did not contain a proper Ed25519 private key banner")

	ErrNoPeerStaticKey = errors.New("no peer static key was present")
	ErrNoPayload       = errors.New("provided payload was empty")

	ErrMissingDetails  = errors.New("certificate did not contain details")
	ErrEmptySignature  = errors.New("empty signature")
	ErrEmptyRawDetails = errors.New("empty rawDetails not allowed")
)

type ErrInvalidCertificateProperties struct {
	str string
}

func NewErrInvalidCertificateProperties(format string, a ...any) error {
	return &ErrInvalidCertificateProperties{fmt.Sprintf(format, a...)}
}

func (e *ErrInvalidCertificateProperties) Error() string {
	return e.str
}
