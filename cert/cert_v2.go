package cert

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/curve25519"
)

const (
	classConstructed     = 0x20
	classContextSpecific = 0x80

	TagCertDetails   = 0 | classConstructed | classContextSpecific
	TagCertCurve     = 1 | classContextSpecific
	TagCertPublicKey = 2 | classContextSpecific
	TagCertSignature = 3 | classContextSpecific

	TagDetailsName           = 0 | classContextSpecific
	TagDetailsNetworks       = 1 | classConstructed | classContextSpecific
	TagDetailsUnsafeNetworks = 2 | classConstructed | classContextSpecific
	TagDetailsGroups         = 3 | classConstructed | classContextSpecific
	TagDetailsIsCA           = 4 | classContextSpecific
	TagDetailsNotBefore      = 5 | classContextSpecific
	TagDetailsNotAfter       = 6 | classContextSpecific
	TagDetailsIssuer         = 7 | classContextSpecific
)

const (
	// MaxCertificateSize is the maximum length a valid certificate can be
	MaxCertificateSize = 65536

	// MaxNameLength is limited to a maximum realistic DNS domain name to help facilitate DNS systems
	MaxNameLength = 253

	// MaxNetworkLength is the maximum length a network value can be.
	// 16 bytes for an ipv6 address + 1 byte for the prefix length
	MaxNetworkLength = 17
)

type certificateV2 struct {
	details detailsV2

	// RawDetails contains the entire asn.1 DER encoded Details struct
	// This is to benefit forwards compatibility in signature checking.
	// signature(RawDetails + Curve + PublicKey) == Signature
	rawDetails []byte
	curve      Curve
	publicKey  []byte
	signature  []byte
}

type detailsV2 struct {
	name           string
	networks       []netip.Prefix // MUST BE SORTED
	unsafeNetworks []netip.Prefix // MUST BE SORTED
	groups         []string
	isCA           bool
	notBefore      time.Time
	notAfter       time.Time
	issuer         string
}

func (c *certificateV2) Version() Version {
	return Version2
}

func (c *certificateV2) Curve() Curve {
	return c.curve
}

func (c *certificateV2) Groups() []string {
	return c.details.groups
}

func (c *certificateV2) IsCA() bool {
	return c.details.isCA
}

func (c *certificateV2) Issuer() string {
	return c.details.issuer
}

func (c *certificateV2) Name() string {
	return c.details.name
}

func (c *certificateV2) Networks() []netip.Prefix {
	return c.details.networks
}

func (c *certificateV2) NotAfter() time.Time {
	return c.details.notAfter
}

func (c *certificateV2) NotBefore() time.Time {
	return c.details.notBefore
}

func (c *certificateV2) PublicKey() []byte {
	return c.publicKey
}

func (c *certificateV2) Signature() []byte {
	return c.signature
}

func (c *certificateV2) UnsafeNetworks() []netip.Prefix {
	return c.details.unsafeNetworks
}

func (c *certificateV2) Fingerprint() (string, error) {
	if len(c.rawDetails) == 0 {
		return "", ErrMissingDetails
	}

	b := make([]byte, len(c.rawDetails)+1+len(c.publicKey)+len(c.signature))
	copy(b, c.rawDetails)
	b[len(c.rawDetails)] = byte(c.curve)
	copy(b[len(c.rawDetails)+1:], c.publicKey)
	copy(b[len(c.rawDetails)+1+len(c.publicKey):], c.signature)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (c *certificateV2) CheckSignature(key []byte) bool {
	if len(c.rawDetails) == 0 {
		return false
	}
	b := make([]byte, len(c.rawDetails)+1+len(c.publicKey))
	copy(b, c.rawDetails)
	b[len(c.rawDetails)] = byte(c.curve)
	copy(b[len(c.rawDetails)+1:], c.publicKey)

	switch c.curve {
	case Curve_CURVE25519:
		return ed25519.Verify(key, b, c.signature)
	case Curve_P256:
		x, y := elliptic.Unmarshal(elliptic.P256(), key)
		pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		hashed := sha256.Sum256(b)
		return ecdsa.VerifyASN1(pubKey, hashed[:], c.signature)
	default:
		return false
	}
}

func (c *certificateV2) Expired(t time.Time) bool {
	return c.details.notBefore.After(t) || c.details.notAfter.Before(t)
}

func (c *certificateV2) VerifyPrivateKey(curve Curve, key []byte) error {
	if curve != c.curve {
		return ErrPublicPrivateCurveMismatch
	}
	if c.details.isCA {
		switch curve {
		case Curve_CURVE25519:
			// the call to PublicKey below will panic slice bounds out of range otherwise
			if len(key) != ed25519.PrivateKeySize {
				return ErrInvalidPrivateKey
			}

			if !ed25519.PublicKey(c.publicKey).Equal(ed25519.PrivateKey(key).Public()) {
				return ErrPublicPrivateKeyMismatch
			}
		case Curve_P256:
			privkey, err := ecdh.P256().NewPrivateKey(key)
			if err != nil {
				return ErrInvalidPrivateKey
			}
			pub := privkey.PublicKey().Bytes()
			if !bytes.Equal(pub, c.publicKey) {
				return ErrPublicPrivateKeyMismatch
			}
		default:
			return fmt.Errorf("invalid curve: %s", curve)
		}
		return nil
	}

	var pub []byte
	switch curve {
	case Curve_CURVE25519:
		var err error
		pub, err = curve25519.X25519(key, curve25519.Basepoint)
		if err != nil {
			return ErrInvalidPrivateKey
		}
	case Curve_P256:
		privkey, err := ecdh.P256().NewPrivateKey(key)
		if err != nil {
			return ErrInvalidPrivateKey
		}
		pub = privkey.PublicKey().Bytes()
	default:
		return fmt.Errorf("invalid curve: %s", curve)
	}
	if !bytes.Equal(pub, c.publicKey) {
		return ErrPublicPrivateKeyMismatch
	}

	return nil
}

func (c *certificateV2) String() string {
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

func (c *certificateV2) MarshalForHandshakes() ([]byte, error) {
	if c.rawDetails == nil {
		return nil, ErrEmptyRawDetails
	}
	var b cryptobyte.Builder
	// Outermost certificate
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

		// Add the cert details which is already marshalled
		b.AddBytes(c.rawDetails)

		// Skipping the curve and public key since those come across in a different part of the handshake

		// Add the signature
		b.AddASN1(TagCertSignature, func(b *cryptobyte.Builder) {
			b.AddBytes(c.signature)
		})
	})

	return b.Bytes()
}

func (c *certificateV2) Marshal() ([]byte, error) {
	if c.rawDetails == nil {
		return nil, ErrEmptyRawDetails
	}
	var b cryptobyte.Builder
	// Outermost certificate
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

		// Add the cert details which is already marshalled
		b.AddBytes(c.rawDetails)

		// Add the curve only if its not the default value
		if c.curve != Curve_CURVE25519 {
			b.AddASN1(TagCertCurve, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte{byte(c.curve)})
			})
		}

		// Add the public key if it is not empty
		if c.publicKey != nil {
			b.AddASN1(TagCertPublicKey, func(b *cryptobyte.Builder) {
				b.AddBytes(c.publicKey)
			})
		}

		// Add the signature
		b.AddASN1(TagCertSignature, func(b *cryptobyte.Builder) {
			b.AddBytes(c.signature)
		})
	})

	return b.Bytes()
}

func (c *certificateV2) MarshalPEM() ([]byte, error) {
	b, err := c.Marshal()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: CertificateV2Banner, Bytes: b}), nil
}

func (c *certificateV2) MarshalJSON() ([]byte, error) {
	b, err := c.marshalJSON()
	if err != nil {
		return nil, err
	}
	return json.Marshal(b)
}

func (c *certificateV2) marshalJSON() (m, error) {
	fp, err := c.Fingerprint()
	if err != nil {
		return nil, err
	}

	return m{
		"details": m{
			"name":           c.details.name,
			"networks":       c.details.networks,
			"unsafeNetworks": c.details.unsafeNetworks,
			"groups":         c.details.groups,
			"notBefore":      c.details.notBefore,
			"notAfter":       c.details.notAfter,
			"isCa":           c.details.isCA,
			"issuer":         c.details.issuer,
		},
		"version":     Version2,
		"publicKey":   fmt.Sprintf("%x", c.publicKey),
		"curve":       c.curve.String(),
		"fingerprint": fp,
		"signature":   fmt.Sprintf("%x", c.Signature()),
	}, nil
}

func (c *certificateV2) Copy() Certificate {
	nc := &certificateV2{
		details: detailsV2{
			name:      c.details.name,
			notBefore: c.details.notBefore,
			notAfter:  c.details.notAfter,
			isCA:      c.details.isCA,
			issuer:    c.details.issuer,
		},
		curve:      c.curve,
		publicKey:  make([]byte, len(c.publicKey)),
		signature:  make([]byte, len(c.signature)),
		rawDetails: make([]byte, len(c.rawDetails)),
	}

	if c.details.groups != nil {
		nc.details.groups = make([]string, len(c.details.groups))
		copy(nc.details.groups, c.details.groups)
	}

	if c.details.networks != nil {
		nc.details.networks = make([]netip.Prefix, len(c.details.networks))
		copy(nc.details.networks, c.details.networks)
	}

	if c.details.unsafeNetworks != nil {
		nc.details.unsafeNetworks = make([]netip.Prefix, len(c.details.unsafeNetworks))
		copy(nc.details.unsafeNetworks, c.details.unsafeNetworks)
	}

	copy(nc.rawDetails, c.rawDetails)
	copy(nc.signature, c.signature)
	copy(nc.publicKey, c.publicKey)

	return nc
}

func (c *certificateV2) fromTBSCertificate(t *TBSCertificate) error {
	c.details = detailsV2{
		name:           t.Name,
		networks:       t.Networks,
		unsafeNetworks: t.UnsafeNetworks,
		groups:         t.Groups,
		isCA:           t.IsCA,
		notBefore:      t.NotBefore,
		notAfter:       t.NotAfter,
		issuer:         t.issuer,
	}
	c.curve = t.Curve
	c.publicKey = t.PublicKey
	return c.validate()
}

func (c *certificateV2) validate() error {
	// Empty names are allowed

	if len(c.publicKey) == 0 {
		return ErrInvalidPublicKey
	}

	if !c.details.isCA && len(c.details.networks) == 0 {
		return NewErrInvalidCertificateProperties("non-CA certificate must contain at least 1 network")
	}

	hasV4Networks := false
	hasV6Networks := false
	for _, network := range c.details.networks {
		if !network.IsValid() || !network.Addr().IsValid() {
			return NewErrInvalidCertificateProperties("invalid network: %s", network)
		}

		if network.Addr().IsUnspecified() {
			return NewErrInvalidCertificateProperties("non-CA certificates must not use the zero address as a network: %s", network)
		}

		if network.Addr().Zone() != "" {
			return NewErrInvalidCertificateProperties("networks may not contain zones: %s", network)
		}

		if network.Addr().Is4In6() {
			return NewErrInvalidCertificateProperties("4in6 networks are not allowed: %s", network)
		}

		hasV4Networks = hasV4Networks || network.Addr().Is4()
		hasV6Networks = hasV6Networks || network.Addr().Is6()
	}

	slices.SortFunc(c.details.networks, comparePrefix)
	err := findDuplicatePrefix(c.details.networks)
	if err != nil {
		return err
	}

	for _, network := range c.details.unsafeNetworks {
		if !network.IsValid() || !network.Addr().IsValid() {
			return NewErrInvalidCertificateProperties("invalid unsafe network: %s", network)
		}

		if network.Addr().Zone() != "" {
			return NewErrInvalidCertificateProperties("unsafe networks may not contain zones: %s", network)
		}

		if !c.details.isCA {
			if network.Addr().Is6() {
				if !hasV6Networks {
					return NewErrInvalidCertificateProperties("IPv6 unsafe networks require an IPv6 address assignment: %s", network)
				}
			} else if network.Addr().Is4() {
				if !hasV4Networks {
					return NewErrInvalidCertificateProperties("IPv4 unsafe networks require an IPv4 address assignment: %s", network)
				}
			}
		}
	}

	slices.SortFunc(c.details.unsafeNetworks, comparePrefix)
	err = findDuplicatePrefix(c.details.unsafeNetworks)
	if err != nil {
		return err
	}

	return nil
}

func (c *certificateV2) marshalForSigning() ([]byte, error) {
	d, err := c.details.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshalling certificate details failed: %w", err)
	}
	c.rawDetails = d

	b := make([]byte, len(c.rawDetails)+1+len(c.publicKey))
	copy(b, c.rawDetails)
	b[len(c.rawDetails)] = byte(c.curve)
	copy(b[len(c.rawDetails)+1:], c.publicKey)
	return b, nil
}

func (c *certificateV2) setSignature(b []byte) error {
	if len(b) == 0 {
		return ErrEmptySignature
	}
	c.signature = b
	return nil
}

func (d *detailsV2) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	var err error

	// Details are a structure
	b.AddASN1(TagCertDetails, func(b *cryptobyte.Builder) {

		// Add the name
		b.AddASN1(TagDetailsName, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(d.name))
		})

		// Add the networks if any exist
		if len(d.networks) > 0 {
			b.AddASN1(TagDetailsNetworks, func(b *cryptobyte.Builder) {
				for _, n := range d.networks {
					sb, innerErr := n.MarshalBinary()
					if innerErr != nil {
						// MarshalBinary never returns an error
						err = fmt.Errorf("unable to marshal network: %w", innerErr)
						return
					}
					b.AddASN1OctetString(sb)
				}
			})
		}

		// Add the unsafe networks if any exist
		if len(d.unsafeNetworks) > 0 {
			b.AddASN1(TagDetailsUnsafeNetworks, func(b *cryptobyte.Builder) {
				for _, n := range d.unsafeNetworks {
					sb, innerErr := n.MarshalBinary()
					if innerErr != nil {
						// MarshalBinary never returns an error
						err = fmt.Errorf("unable to marshal unsafe network: %w", innerErr)
						return
					}
					b.AddASN1OctetString(sb)
				}
			})
		}

		// Add groups if any exist
		if len(d.groups) > 0 {
			b.AddASN1(TagDetailsGroups, func(b *cryptobyte.Builder) {
				for _, group := range d.groups {
					b.AddASN1(asn1.UTF8String, func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(group))
					})
				}
			})
		}

		// Add IsCA only if true
		if d.isCA {
			b.AddASN1(TagDetailsIsCA, func(b *cryptobyte.Builder) {
				b.AddUint8(0xff)
			})
		}

		// Add not before
		b.AddASN1Int64WithTag(d.notBefore.Unix(), TagDetailsNotBefore)

		// Add not after
		b.AddASN1Int64WithTag(d.notAfter.Unix(), TagDetailsNotAfter)

		// Add the issuer if present
		if d.issuer != "" {
			issuerBytes, innerErr := hex.DecodeString(d.issuer)
			if innerErr != nil {
				err = fmt.Errorf("failed to decode issuer: %w", innerErr)
				return
			}
			b.AddASN1(TagDetailsIssuer, func(b *cryptobyte.Builder) {
				b.AddBytes(issuerBytes)
			})
		}
	})

	if err != nil {
		return nil, err
	}

	return b.Bytes()
}

func unmarshalCertificateV2(b []byte, publicKey []byte, curve Curve) (*certificateV2, error) {
	l := len(b)
	if l == 0 || l > MaxCertificateSize {
		return nil, ErrBadFormat
	}

	input := cryptobyte.String(b)
	// Open the envelope
	if !input.ReadASN1(&input, asn1.SEQUENCE) || input.Empty() {
		return nil, ErrBadFormat
	}

	// Grab the cert details, we need to preserve the tag and length
	var rawDetails cryptobyte.String
	if !input.ReadASN1Element(&rawDetails, TagCertDetails) || rawDetails.Empty() {
		return nil, ErrBadFormat
	}

	//Maybe grab the curve
	var rawCurve byte
	if !readOptionalASN1Byte(&input, &rawCurve, TagCertCurve, byte(curve)) {
		return nil, ErrBadFormat
	}
	curve = Curve(rawCurve)

	// Maybe grab the public key
	var rawPublicKey cryptobyte.String
	if len(publicKey) > 0 {
		rawPublicKey = publicKey
	} else if !input.ReadOptionalASN1(&rawPublicKey, nil, TagCertPublicKey) {
		return nil, ErrBadFormat
	}

	if len(rawPublicKey) == 0 {
		return nil, ErrBadFormat
	}

	// Grab the signature
	var rawSignature cryptobyte.String
	if !input.ReadASN1(&rawSignature, TagCertSignature) || rawSignature.Empty() {
		return nil, ErrBadFormat
	}

	// Finally unmarshal the details
	details, err := unmarshalDetails(rawDetails)
	if err != nil {
		return nil, err
	}

	c := &certificateV2{
		details:    details,
		rawDetails: rawDetails,
		curve:      curve,
		publicKey:  rawPublicKey,
		signature:  rawSignature,
	}

	err = c.validate()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func unmarshalDetails(b cryptobyte.String) (detailsV2, error) {
	// Open the envelope
	if !b.ReadASN1(&b, TagCertDetails) || b.Empty() {
		return detailsV2{}, ErrBadFormat
	}

	// Read the name
	var name cryptobyte.String
	if !b.ReadASN1(&name, TagDetailsName) || name.Empty() || len(name) > MaxNameLength {
		return detailsV2{}, ErrBadFormat
	}

	// Read the network addresses
	var subString cryptobyte.String
	var found bool

	if !b.ReadOptionalASN1(&subString, &found, TagDetailsNetworks) {
		return detailsV2{}, ErrBadFormat
	}

	var networks []netip.Prefix
	var val cryptobyte.String
	if found {
		for !subString.Empty() {
			if !subString.ReadASN1(&val, asn1.OCTET_STRING) || val.Empty() || len(val) > MaxNetworkLength {
				return detailsV2{}, ErrBadFormat
			}

			var n netip.Prefix
			if err := n.UnmarshalBinary(val); err != nil {
				return detailsV2{}, ErrBadFormat
			}
			networks = append(networks, n)
		}
	}

	// Read out any unsafe networks
	if !b.ReadOptionalASN1(&subString, &found, TagDetailsUnsafeNetworks) {
		return detailsV2{}, ErrBadFormat
	}

	var unsafeNetworks []netip.Prefix
	if found {
		for !subString.Empty() {
			if !subString.ReadASN1(&val, asn1.OCTET_STRING) || val.Empty() || len(val) > MaxNetworkLength {
				return detailsV2{}, ErrBadFormat
			}

			var n netip.Prefix
			if err := n.UnmarshalBinary(val); err != nil {
				return detailsV2{}, ErrBadFormat
			}
			unsafeNetworks = append(unsafeNetworks, n)
		}
	}

	// Read out any groups
	if !b.ReadOptionalASN1(&subString, &found, TagDetailsGroups) {
		return detailsV2{}, ErrBadFormat
	}

	var groups []string
	if found {
		for !subString.Empty() {
			if !subString.ReadASN1(&val, asn1.UTF8String) || val.Empty() {
				return detailsV2{}, ErrBadFormat
			}
			groups = append(groups, string(val))
		}
	}

	// Read out IsCA
	var isCa bool
	if !readOptionalASN1Boolean(&b, &isCa, TagDetailsIsCA, false) {
		return detailsV2{}, ErrBadFormat
	}

	// Read not before and not after
	var notBefore int64
	if !b.ReadASN1Int64WithTag(&notBefore, TagDetailsNotBefore) {
		return detailsV2{}, ErrBadFormat
	}

	var notAfter int64
	if !b.ReadASN1Int64WithTag(&notAfter, TagDetailsNotAfter) {
		return detailsV2{}, ErrBadFormat
	}

	// Read issuer
	var issuer cryptobyte.String
	if !b.ReadOptionalASN1(&issuer, nil, TagDetailsIssuer) {
		return detailsV2{}, ErrBadFormat
	}

	return detailsV2{
		name:           string(name),
		networks:       networks,
		unsafeNetworks: unsafeNetworks,
		groups:         groups,
		isCA:           isCa,
		notBefore:      time.Unix(notBefore, 0),
		notAfter:       time.Unix(notAfter, 0),
		issuer:         hex.EncodeToString(issuer),
	}, nil
}
