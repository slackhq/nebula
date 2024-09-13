package cert

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

const publicKeyLen = 32

type certificateV1 struct {
	details   detailsV1
	signature []byte
}

type detailsV1 struct {
	Name      string
	Ips       []netip.Prefix
	Subnets   []netip.Prefix
	Groups    []string
	NotBefore time.Time
	NotAfter  time.Time
	PublicKey []byte
	IsCA      bool
	Issuer    string

	Curve Curve
}

type m map[string]interface{}

func (c *certificateV1) Version() Version {
	return Version1
}

func (c *certificateV1) Curve() Curve {
	return c.details.Curve
}

func (c *certificateV1) Groups() []string {
	return c.details.Groups
}

func (c *certificateV1) IsCA() bool {
	return c.details.IsCA
}

func (c *certificateV1) Issuer() string {
	return c.details.Issuer
}

func (c *certificateV1) Name() string {
	return c.details.Name
}

func (c *certificateV1) Networks() []netip.Prefix {
	return c.details.Ips
}

func (c *certificateV1) NotAfter() time.Time {
	return c.details.NotAfter
}

func (c *certificateV1) NotBefore() time.Time {
	return c.details.NotBefore
}

func (c *certificateV1) PublicKey() []byte {
	return c.details.PublicKey
}

func (c *certificateV1) Signature() []byte {
	return c.signature
}

func (c *certificateV1) UnsafeNetworks() []netip.Prefix {
	return c.details.Subnets
}

func (c *certificateV1) Fingerprint() (string, error) {
	b, err := c.Marshal()
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (c *certificateV1) CheckSignature(key []byte) bool {
	b, err := proto.Marshal(c.getRawDetails())
	if err != nil {
		return false
	}
	switch c.details.Curve {
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

func (c *certificateV1) Expired(t time.Time) bool {
	return c.details.NotBefore.After(t) || c.details.NotAfter.Before(t)
}

func (c *certificateV1) VerifyPrivateKey(curve Curve, key []byte) error {
	if curve != c.details.Curve {
		return fmt.Errorf("curve in cert and private key supplied don't match")
	}
	if c.details.IsCA {
		switch curve {
		case Curve_CURVE25519:
			// the call to PublicKey below will panic slice bounds out of range otherwise
			if len(key) != ed25519.PrivateKeySize {
				return fmt.Errorf("key was not 64 bytes, is invalid ed25519 private key")
			}

			if !ed25519.PublicKey(c.details.PublicKey).Equal(ed25519.PrivateKey(key).Public()) {
				return fmt.Errorf("public key in cert and private key supplied don't match")
			}
		case Curve_P256:
			privkey, err := ecdh.P256().NewPrivateKey(key)
			if err != nil {
				return fmt.Errorf("cannot parse private key as P256")
			}
			pub := privkey.PublicKey().Bytes()
			if !bytes.Equal(pub, c.details.PublicKey) {
				return fmt.Errorf("public key in cert and private key supplied don't match")
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
			return err
		}
	case Curve_P256:
		privkey, err := ecdh.P256().NewPrivateKey(key)
		if err != nil {
			return err
		}
		pub = privkey.PublicKey().Bytes()
	default:
		return fmt.Errorf("invalid curve: %s", curve)
	}
	if !bytes.Equal(pub, c.details.PublicKey) {
		return fmt.Errorf("public key in cert and private key supplied don't match")
	}

	return nil
}

// getRawDetails marshals the raw details into protobuf ready struct
func (c *certificateV1) getRawDetails() *RawNebulaCertificateDetails {
	rd := &RawNebulaCertificateDetails{
		Name:      c.details.Name,
		Groups:    c.details.Groups,
		NotBefore: c.details.NotBefore.Unix(),
		NotAfter:  c.details.NotAfter.Unix(),
		PublicKey: make([]byte, len(c.details.PublicKey)),
		IsCA:      c.details.IsCA,
		Curve:     c.details.Curve,
	}

	for _, ipNet := range c.details.Ips {
		mask := net.CIDRMask(ipNet.Bits(), ipNet.Addr().BitLen())
		rd.Ips = append(rd.Ips, addr2int(ipNet.Addr()), ip2int(mask))
	}

	for _, ipNet := range c.details.Subnets {
		mask := net.CIDRMask(ipNet.Bits(), ipNet.Addr().BitLen())
		rd.Subnets = append(rd.Subnets, addr2int(ipNet.Addr()), ip2int(mask))
	}

	copy(rd.PublicKey, c.details.PublicKey[:])

	// I know, this is terrible
	rd.Issuer, _ = hex.DecodeString(c.details.Issuer)

	return rd
}

func (c *certificateV1) String() string {
	if c == nil {
		return "Certificate {}\n"
	}

	s := "NebulaCertificate {\n"
	s += "\tDetails {\n"
	s += fmt.Sprintf("\t\tName: %v\n", c.details.Name)

	if len(c.details.Ips) > 0 {
		s += "\t\tIps: [\n"
		for _, ip := range c.details.Ips {
			s += fmt.Sprintf("\t\t\t%v\n", ip.String())
		}
		s += "\t\t]\n"
	} else {
		s += "\t\tIps: []\n"
	}

	if len(c.details.Subnets) > 0 {
		s += "\t\tSubnets: [\n"
		for _, ip := range c.details.Subnets {
			s += fmt.Sprintf("\t\t\t%v\n", ip.String())
		}
		s += "\t\t]\n"
	} else {
		s += "\t\tSubnets: []\n"
	}

	if len(c.details.Groups) > 0 {
		s += "\t\tGroups: [\n"
		for _, g := range c.details.Groups {
			s += fmt.Sprintf("\t\t\t\"%v\"\n", g)
		}
		s += "\t\t]\n"
	} else {
		s += "\t\tGroups: []\n"
	}

	s += fmt.Sprintf("\t\tNot before: %v\n", c.details.NotBefore)
	s += fmt.Sprintf("\t\tNot After: %v\n", c.details.NotAfter)
	s += fmt.Sprintf("\t\tIs CA: %v\n", c.details.IsCA)
	s += fmt.Sprintf("\t\tIssuer: %s\n", c.details.Issuer)
	s += fmt.Sprintf("\t\tPublic key: %x\n", c.details.PublicKey)
	s += fmt.Sprintf("\t\tCurve: %s\n", c.details.Curve)
	s += "\t}\n"
	fp, err := c.Fingerprint()
	if err == nil {
		s += fmt.Sprintf("\tFingerprint: %s\n", fp)
	}
	s += fmt.Sprintf("\tSignature: %x\n", c.Signature())
	s += "}"

	return s
}

func (c *certificateV1) MarshalForHandshakes() ([]byte, error) {
	pubKey := c.details.PublicKey
	c.details.PublicKey = nil
	rawCertNoKey, err := c.Marshal()
	if err != nil {
		return nil, err
	}
	c.details.PublicKey = pubKey
	return rawCertNoKey, nil
}

func (c *certificateV1) Marshal() ([]byte, error) {
	rc := RawNebulaCertificate{
		Details:   c.getRawDetails(),
		Signature: c.signature,
	}

	return proto.Marshal(&rc)
}

func (c *certificateV1) MarshalPEM() ([]byte, error) {
	b, err := c.Marshal()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: CertificateBanner, Bytes: b}), nil
}

func (c *certificateV1) MarshalJSON() ([]byte, error) {
	fp, _ := c.Fingerprint()
	jc := m{
		"details": m{
			"name":      c.details.Name,
			"ips":       c.details.Ips,
			"subnets":   c.details.Subnets,
			"groups":    c.details.Groups,
			"notBefore": c.details.NotBefore,
			"notAfter":  c.details.NotAfter,
			"publicKey": fmt.Sprintf("%x", c.details.PublicKey),
			"isCa":      c.details.IsCA,
			"issuer":    c.details.Issuer,
			"curve":     c.details.Curve.String(),
		},
		"fingerprint": fp,
		"signature":   fmt.Sprintf("%x", c.Signature()),
	}
	return json.Marshal(jc)
}

func (c *certificateV1) Copy() Certificate {
	nc := &certificateV1{
		details: detailsV1{
			Name:      c.details.Name,
			Groups:    make([]string, len(c.details.Groups)),
			Ips:       make([]netip.Prefix, len(c.details.Ips)),
			Subnets:   make([]netip.Prefix, len(c.details.Subnets)),
			NotBefore: c.details.NotBefore,
			NotAfter:  c.details.NotAfter,
			PublicKey: make([]byte, len(c.details.PublicKey)),
			IsCA:      c.details.IsCA,
			Issuer:    c.details.Issuer,
			Curve:     c.details.Curve,
		},
		signature: make([]byte, len(c.signature)),
	}

	copy(nc.signature, c.signature)
	copy(nc.details.Groups, c.details.Groups)
	copy(nc.details.PublicKey, c.details.PublicKey)
	copy(nc.details.Ips, c.details.Ips)
	copy(nc.details.Subnets, c.details.Subnets)

	return nc
}

func (c *certificateV1) fromTBSCertificate(t *TBSCertificate) error {
	c.details = detailsV1{
		Name:      t.Name,
		Ips:       t.Networks,
		Subnets:   t.UnsafeNetworks,
		Groups:    t.Groups,
		NotBefore: t.NotBefore,
		NotAfter:  t.NotAfter,
		PublicKey: t.PublicKey,
		IsCA:      t.IsCA,
		Curve:     t.Curve,
		Issuer:    t.issuer,
	}

	return nil
}

func (c *certificateV1) marshalForSigning() ([]byte, error) {
	b, err := proto.Marshal(c.getRawDetails())
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (c *certificateV1) setSignature(b []byte) error {
	c.signature = b
	return nil
}

// unmarshalCertificateV1 will unmarshal a protobuf byte representation of a nebula cert
// if the publicKey is provided here then it is not required to be present in `b`
func unmarshalCertificateV1(b []byte, publicKey []byte) (*certificateV1, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("nil byte array")
	}
	var rc RawNebulaCertificate
	err := proto.Unmarshal(b, &rc)
	if err != nil {
		return nil, err
	}

	if rc.Details == nil {
		return nil, fmt.Errorf("encoded Details was nil")
	}

	if len(rc.Details.Ips)%2 != 0 {
		return nil, fmt.Errorf("encoded IPs should be in pairs, an odd number was found")
	}

	if len(rc.Details.Subnets)%2 != 0 {
		return nil, fmt.Errorf("encoded Subnets should be in pairs, an odd number was found")
	}

	nc := certificateV1{
		details: detailsV1{
			Name:      rc.Details.Name,
			Groups:    make([]string, len(rc.Details.Groups)),
			Ips:       make([]netip.Prefix, len(rc.Details.Ips)/2),
			Subnets:   make([]netip.Prefix, len(rc.Details.Subnets)/2),
			NotBefore: time.Unix(rc.Details.NotBefore, 0),
			NotAfter:  time.Unix(rc.Details.NotAfter, 0),
			PublicKey: make([]byte, len(rc.Details.PublicKey)),
			IsCA:      rc.Details.IsCA,
			Curve:     rc.Details.Curve,
		},
		signature: make([]byte, len(rc.Signature)),
	}

	copy(nc.signature, rc.Signature)
	copy(nc.details.Groups, rc.Details.Groups)
	nc.details.Issuer = hex.EncodeToString(rc.Details.Issuer)

	if len(publicKey) > 0 {
		nc.details.PublicKey = publicKey
	}

	copy(nc.details.PublicKey, rc.Details.PublicKey)

	var ip netip.Addr
	for i, rawIp := range rc.Details.Ips {
		if i%2 == 0 {
			ip = int2addr(rawIp)
		} else {
			ones, _ := net.IPMask(int2ip(rawIp)).Size()
			nc.details.Ips[i/2] = netip.PrefixFrom(ip, ones)
		}
	}

	for i, rawIp := range rc.Details.Subnets {
		if i%2 == 0 {
			ip = int2addr(rawIp)
		} else {
			ones, _ := net.IPMask(int2ip(rawIp)).Size()
			nc.details.Subnets[i/2] = netip.PrefixFrom(ip, ones)
		}
	}

	return &nc, nil
}

func ip2int(ip []byte) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func addr2int(addr netip.Addr) uint32 {
	b := addr.Unmap().As4()
	return binary.BigEndian.Uint32(b[:])
}

func int2addr(nn uint32) netip.Addr {
	ip := [4]byte{}
	binary.BigEndian.PutUint32(ip[:], nn)
	return netip.AddrFrom4(ip).Unmap()
}
