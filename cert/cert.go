package cert

import (
	"net/netip"
	"time"
)

type Version int

const (
	Version1 Version = 1
	Version2 Version = 2
)

type Certificate interface {
	//TODO: describe this
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
	Issuer() string //TODO: string or bytes?

	// PublicKey is the raw bytes to be used in asymmetric cryptographic operations.
	PublicKey() []byte

	// Curve identifies which curve was used for the PublicKey and Signature.
	Curve() Curve

	// Signature is the cryptographic seal for all the details of this certificate.
	// CheckSignature can be used to verify that the details of this certificate are valid.
	Signature() []byte //TODO: string or bytes?

	// CheckSignature will check that the certificate Signature() matches the
	// computed signature. A true result means this certificate has not been tampered with.
	CheckSignature(signingPublicKey []byte) bool

	// Sha256Sum returns the hex encoded sha256 sum of the certificate.
	// This acts as a unique fingerprint and can be used to blocklist certificates.
	Sha256Sum() (string, error)

	// Expired tests if the certificate is valid for the provided time.
	Expired(t time.Time) bool

	// CheckRootConstraints tests if the certificate meets all constraints in the
	// signing certificate, returning the first violated constraint or nil if the
	// certificate conforms to all constraints.
	//TODO: feels better to have this on the CAPool I think
	CheckRootConstraints(signer Certificate) error

	//TODO
	VerifyPrivateKey(curve Curve, privateKey []byte) error

	// Marshal will return the byte representation of this certificate
	// This is primarily the format transmitted on the wire.
	Marshal() ([]byte, error)

	// MarshalForHandshakes prepares the bytes needed to use directly in a handshake
	MarshalForHandshakes() ([]byte, error)

	// MarshalToPEM will return a PEM encoded representation of this certificate
	// This is primarily the format stored on disk
	//TODO: MarshalPEM?
	MarshalToPEM() ([]byte, error)

	// MarshalJSON will return the json representation of this certificate
	MarshalJSON() ([]byte, error)

	// String will return a human-readable representation of this certificate
	String() string

	//TODO
	Copy() Certificate
}

// CachedCertificate represents a verified certificate with some cached fields to improve
// performance.
type CachedCertificate struct {
	Certificate    Certificate
	InvertedGroups map[string]struct{}
	ShaSum         string
	signerShaSum   string
}

// TODO:
func UnmarshalCertificate(b []byte) (Certificate, error) {
	c, err := unmarshalCertificateV1(b, true)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// TODO:
func UnmarshalCertificateFromHandshake(b []byte, publicKey []byte) (Certificate, error) {
	c, err := unmarshalCertificateV1(b, false)
	if err != nil {
		return nil, err
	}
	c.details.PublicKey = publicKey
	return c, nil
}
