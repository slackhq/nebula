package cert

import (
	"fmt"
	"net/netip"
	"time"
)

type Version uint8

const (
	VersionPre1 Version = 0
	Version1    Version = 1
	Version2    Version = 2
)

type Certificate interface {
	// Version defines the underlying certificate structure and wire protocol version
	// Version1 certificates are ipv4 only and uses protobuf serialization
	// Version2 certificates are ipv4 or ipv6 and uses asn.1 serialization
	Version() Version

	// Name is the human-readable name that identifies this certificate.
	Name() string

	// Networks is a list of ip addresses and network sizes assigned to this certificate.
	// If IsCA is true then certificates signed by this CA can only have ip addresses and
	// networks that are contained by an entry in this list.
	Networks() []netip.Prefix

	// UnsafeNetworks is a list of networks that this host can act as an unsafe router for.
	// If IsCA is true then certificates signed by this CA can only have networks that are
	// contained by an entry in this list.
	UnsafeNetworks() []netip.Prefix

	// Groups is a list of identities that can be used to write more general firewall rule
	// definitions.
	// If IsCA is true then certificates signed by this CA can only use groups that are
	// in this list.
	Groups() []string

	// IsCA signifies if this is a certificate authority (true) or a host certificate (false).
	// It is invalid to use a CA certificate as a host certificate.
	IsCA() bool

	// NotBefore is the time at which this certificate becomes valid.
	// If IsCA is true then certificate signed by this CA can not have a time before this.
	NotBefore() time.Time

	// NotAfter is the time at which this certificate becomes invalid.
	// If IsCA is true then certificate signed by this CA can not have a time after this.
	NotAfter() time.Time

	// Issuer is the fingerprint of the CA that signed this certificate.
	// If IsCA is true then this will be empty.
	Issuer() string

	// PublicKey is the raw bytes to be used in asymmetric cryptographic operations.
	PublicKey() []byte

	// MarshalPublicKeyPEM is the value of PublicKey marshalled to PEM
	MarshalPublicKeyPEM() []byte

	// Curve identifies which curve was used for the PublicKey and Signature.
	Curve() Curve

	// Signature is the cryptographic seal for all the details of this certificate.
	// CheckSignature can be used to verify that the details of this certificate are valid.
	Signature() []byte

	// CheckSignature will check that the certificate Signature() matches the
	// computed signature. A true result means this certificate has not been tampered with.
	CheckSignature(signingPublicKey []byte) bool

	// Fingerprint returns the hex encoded sha256 sum of the certificate.
	// This acts as a unique fingerprint and can be used to blocklist certificates.
	Fingerprint() (string, error)

	// Expired tests if the certificate is valid for the provided time.
	Expired(t time.Time) bool

	// VerifyPrivateKey returns an error if the private key is not a pair with the certificates public key.
	VerifyPrivateKey(curve Curve, privateKey []byte) error

	// Marshal will return the byte representation of this certificate
	// This is primarily the format transmitted on the wire.
	Marshal() ([]byte, error)

	// MarshalForHandshakes prepares the bytes needed to use directly in a handshake
	MarshalForHandshakes() ([]byte, error)

	// MarshalPEM will return a PEM encoded representation of this certificate
	// This is primarily the format stored on disk
	MarshalPEM() ([]byte, error)

	// MarshalJSON will return the json representation of this certificate
	MarshalJSON() ([]byte, error)

	// String will return a human-readable representation of this certificate
	String() string

	// Copy creates a copy of the certificate
	Copy() Certificate
}

// CachedCertificate represents a verified certificate with some cached fields to improve
// performance.
type CachedCertificate struct {
	Certificate       Certificate
	InvertedGroups    map[string]struct{}
	Fingerprint       string
	signerFingerprint string
}

func (cc *CachedCertificate) String() string {
	return cc.Certificate.String()
}

// Recombine will attempt to unmarshal a certificate received in a handshake.
// Handshakes save space by placing the peers public key in a different part of the packet, we have to
// reassemble the actual certificate structure with that in mind.
// Implementations MUST assert the public key is not in the raw certificate bytes if the passed in public key is not empty.
func Recombine(v Version, rawCertBytes, publicKey []byte, curve Curve) (Certificate, error) {
	if publicKey == nil {
		return nil, ErrNoPeerStaticKey
	}

	if rawCertBytes == nil {
		return nil, ErrNoPayload
	}

	var c Certificate
	var err error

	switch v {
	// Implementations must ensure the result is a valid cert!
	case VersionPre1, Version1:
		c, err = unmarshalCertificateV1(rawCertBytes, publicKey)
	case Version2:
		c, err = unmarshalCertificateV2(rawCertBytes, publicKey, curve)
	default:
		return nil, ErrUnknownVersion
	}

	if err != nil {
		return nil, err
	}

	if c.Curve() != curve {
		return nil, fmt.Errorf("certificate curve %s does not match expected %s", c.Curve().String(), curve.String())
	}

	return c, nil
}
