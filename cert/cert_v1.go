package cert

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/slackhq/nebula/pkclient"
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

func (nc *certificateV1) Version() Version {
	return Version1
}

func (nc *certificateV1) Curve() Curve {
	return nc.details.Curve
}

func (nc *certificateV1) Groups() []string {
	return nc.details.Groups
}

func (nc *certificateV1) IsCA() bool {
	return nc.details.IsCA
}

func (nc *certificateV1) Issuer() string {
	return nc.details.Issuer
}

func (nc *certificateV1) Name() string {
	return nc.details.Name
}

func (nc *certificateV1) Networks() []netip.Prefix {
	return nc.details.Ips
}

func (nc *certificateV1) NotAfter() time.Time {
	return nc.details.NotAfter
}

func (nc *certificateV1) NotBefore() time.Time {
	return nc.details.NotBefore
}

func (nc *certificateV1) PublicKey() []byte {
	return nc.details.PublicKey
}

func (nc *certificateV1) Signature() []byte {
	return nc.signature
}

func (nc *certificateV1) UnsafeNetworks() []netip.Prefix {
	return nc.details.Subnets
}

func (nc *certificateV1) MarshalForHandshakes() ([]byte, error) {
	pubKey := nc.details.PublicKey
	nc.details.PublicKey = nil
	rawCertNoKey, err := nc.Marshal()
	if err != nil {
		return nil, err
	}
	nc.details.PublicKey = pubKey
	return rawCertNoKey, nil
}

// unmarshalCertificateV1 will unmarshal a protobuf byte representation of a nebula cert
func unmarshalCertificateV1(b []byte, assertPublicKey bool) (*certificateV1, error) {
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

	if len(rc.Details.PublicKey) < publicKeyLen && assertPublicKey {
		return nil, fmt.Errorf("Public key was fewer than 32 bytes; %v", len(rc.Details.PublicKey))
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

func signV1(t *TBSCertificate, curve Curve, key []byte, client *pkclient.PKClient) (*certificateV1, error) {
	c := &certificateV1{
		details: detailsV1{
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
		},
	}
	b, err := proto.Marshal(c.getRawDetails())
	if err != nil {
		return nil, err
	}

	var sig []byte

	switch curve {
	case Curve_CURVE25519:
		signer := ed25519.PrivateKey(key)
		sig = ed25519.Sign(signer, b)
	case Curve_P256:
		if client != nil {
			sig, err = client.SignASN1(b)
		} else {
			signer := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
				// ref: https://github.com/golang/go/blob/go1.19/src/crypto/x509/sec1.go#L95
				D: new(big.Int).SetBytes(key),
			}
			// ref: https://github.com/golang/go/blob/go1.19/src/crypto/x509/sec1.go#L119
			signer.X, signer.Y = signer.Curve.ScalarBaseMult(key)

			// We need to hash first for ECDSA
			// - https://pkg.go.dev/crypto/ecdsa#SignASN1
			hashed := sha256.Sum256(b)
			sig, err = ecdsa.SignASN1(rand.Reader, signer, hashed[:])
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("invalid curve: %s", c.details.Curve)
	}

	c.signature = sig
	return c, nil
}

// CheckSignature verifies the signature against the provided public key
func (nc *certificateV1) CheckSignature(key []byte) bool {
	b, err := proto.Marshal(nc.getRawDetails())
	if err != nil {
		return false
	}
	switch nc.details.Curve {
	case Curve_CURVE25519:
		return ed25519.Verify(key, b, nc.signature)
	case Curve_P256:
		x, y := elliptic.Unmarshal(elliptic.P256(), key)
		pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		hashed := sha256.Sum256(b)
		return ecdsa.VerifyASN1(pubKey, hashed[:], nc.signature)
	default:
		return false
	}
}

// Expired will return true if the nebula cert is too young or too old compared to the provided time, otherwise false
func (nc *certificateV1) Expired(t time.Time) bool {
	return nc.details.NotBefore.After(t) || nc.details.NotAfter.Before(t)
}

// CheckRootConstraints returns an error if the certificate violates constraints set on the root (groups, ips, subnets)
// TODO: we could use cachedcert here to make it better, maybe who cares cuz its only once? Or move this entirely to caPool
func (nc *certificateV1) CheckRootConstraints(signer Certificate) error {
	// Make sure this cert wasn't valid before the root
	if signer.NotAfter().Before(nc.details.NotAfter) {
		return fmt.Errorf("certificate expires after signing certificate")
	}

	// Make sure this cert isn't valid after the root
	if signer.NotBefore().After(nc.details.NotBefore) {
		return fmt.Errorf("certificate is valid before the signing certificate")
	}

	// If the signer has a limited set of groups make sure the cert only contains a subset
	groups := signer.Groups()
	if len(groups) > 0 {
		for _, g := range nc.details.Groups {
			if !slices.Contains(groups, g) {
				//TODO: since we no longer pre-compute the inverted groups then this is kind of slow
				return fmt.Errorf("certificate contained a group not present on the signing ca: %s", g)
			}
		}
	}

	// If the signer has a limited set of ip ranges to issue from make sure the cert only contains a subset
	networks := signer.Networks()
	if len(networks) > 0 {
		for _, cNetwork := range nc.details.Ips {
			found := false
			for _, caNetwork := range networks {
				if caNetwork.Contains(cNetwork.Addr()) && caNetwork.Bits() <= cNetwork.Bits() {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("certificate contained an ip assignment outside the limitations of the signing ca: %s", cNetwork.String())
			}
		}
	}

	// If the signer has a limited set of subnet ranges to issue from make sure the cert only contains a subset
	unsafeNetworks := signer.UnsafeNetworks()
	if len(unsafeNetworks) > 0 {
		for _, cNetwork := range nc.details.Subnets {
			found := false
			for _, caNetwork := range unsafeNetworks {
				if caNetwork.Contains(cNetwork.Addr()) && caNetwork.Bits() <= cNetwork.Bits() {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("certificate contained a subnet assignment outside the limitations of the signing ca: %s", cNetwork.String())
			}
		}
	}

	return nil
}

// VerifyPrivateKey checks that the public key in the Nebula certificate and a supplied private key match
func (nc *certificateV1) VerifyPrivateKey(curve Curve, key []byte) error {
	if curve != nc.details.Curve {
		return fmt.Errorf("curve in cert and private key supplied don't match")
	}
	if nc.details.IsCA {
		switch curve {
		case Curve_CURVE25519:
			// the call to PublicKey below will panic slice bounds out of range otherwise
			if len(key) != ed25519.PrivateKeySize {
				return fmt.Errorf("key was not 64 bytes, is invalid ed25519 private key")
			}

			if !ed25519.PublicKey(nc.details.PublicKey).Equal(ed25519.PrivateKey(key).Public()) {
				return fmt.Errorf("public key in cert and private key supplied don't match")
			}
		case Curve_P256:
			privkey, err := ecdh.P256().NewPrivateKey(key)
			if err != nil {
				return fmt.Errorf("cannot parse private key as P256")
			}
			pub := privkey.PublicKey().Bytes()
			if !bytes.Equal(pub, nc.details.PublicKey) {
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
	if !bytes.Equal(pub, nc.details.PublicKey) {
		return fmt.Errorf("public key in cert and private key supplied don't match")
	}

	return nil
}

// String will return a pretty printed representation of a nebula cert
func (nc *certificateV1) String() string {
	if nc == nil {
		return "Certificate {}\n"
	}

	s := "NebulaCertificate {\n"
	s += "\tDetails {\n"
	s += fmt.Sprintf("\t\tName: %v\n", nc.details.Name)

	if len(nc.details.Ips) > 0 {
		s += "\t\tIps: [\n"
		for _, ip := range nc.details.Ips {
			s += fmt.Sprintf("\t\t\t%v\n", ip.String())
		}
		s += "\t\t]\n"
	} else {
		s += "\t\tIps: []\n"
	}

	if len(nc.details.Subnets) > 0 {
		s += "\t\tSubnets: [\n"
		for _, ip := range nc.details.Subnets {
			s += fmt.Sprintf("\t\t\t%v\n", ip.String())
		}
		s += "\t\t]\n"
	} else {
		s += "\t\tSubnets: []\n"
	}

	if len(nc.details.Groups) > 0 {
		s += "\t\tGroups: [\n"
		for _, g := range nc.details.Groups {
			s += fmt.Sprintf("\t\t\t\"%v\"\n", g)
		}
		s += "\t\t]\n"
	} else {
		s += "\t\tGroups: []\n"
	}

	s += fmt.Sprintf("\t\tNot before: %v\n", nc.details.NotBefore)
	s += fmt.Sprintf("\t\tNot After: %v\n", nc.details.NotAfter)
	s += fmt.Sprintf("\t\tIs CA: %v\n", nc.details.IsCA)
	s += fmt.Sprintf("\t\tIssuer: %s\n", nc.details.Issuer)
	s += fmt.Sprintf("\t\tPublic key: %x\n", nc.details.PublicKey)
	s += fmt.Sprintf("\t\tCurve: %s\n", nc.details.Curve)
	s += "\t}\n"
	fp, err := nc.Sha256Sum()
	if err == nil {
		s += fmt.Sprintf("\tFingerprint: %s\n", fp)
	}
	s += fmt.Sprintf("\tSignature: %x\n", nc.Signature())
	s += "}"

	return s
}

// getRawDetails marshals the raw details into protobuf ready struct
func (nc *certificateV1) getRawDetails() *RawNebulaCertificateDetails {
	rd := &RawNebulaCertificateDetails{
		Name:      nc.details.Name,
		Groups:    nc.details.Groups,
		NotBefore: nc.details.NotBefore.Unix(),
		NotAfter:  nc.details.NotAfter.Unix(),
		PublicKey: make([]byte, len(nc.details.PublicKey)),
		IsCA:      nc.details.IsCA,
		Curve:     nc.details.Curve,
	}

	for _, ipNet := range nc.details.Ips {
		mask := net.CIDRMask(ipNet.Bits(), ipNet.Addr().BitLen())
		rd.Ips = append(rd.Ips, addr2int(ipNet.Addr()), ip2int(mask))
	}

	for _, ipNet := range nc.details.Subnets {
		mask := net.CIDRMask(ipNet.Bits(), ipNet.Addr().BitLen())
		rd.Subnets = append(rd.Subnets, addr2int(ipNet.Addr()), ip2int(mask))
	}

	copy(rd.PublicKey, nc.details.PublicKey[:])

	// I know, this is terrible
	rd.Issuer, _ = hex.DecodeString(nc.details.Issuer)

	return rd
}

// Marshal will marshal a nebula cert into a protobuf byte array
func (nc *certificateV1) Marshal() ([]byte, error) {
	rc := RawNebulaCertificate{
		Details:   nc.getRawDetails(),
		Signature: nc.signature,
	}

	return proto.Marshal(&rc)
}

// MarshalToPEM will marshal a nebula cert into a protobuf byte array and pem encode the result
func (nc *certificateV1) MarshalToPEM() ([]byte, error) {
	b, err := nc.Marshal()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: CertificateBanner, Bytes: b}), nil
}

// Sha256Sum calculates a sha-256 sum of the marshaled certificate
func (nc *certificateV1) Sha256Sum() (string, error) {
	b, err := nc.Marshal()
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (nc *certificateV1) MarshalJSON() ([]byte, error) {
	fp, _ := nc.Sha256Sum()
	jc := m{
		"details": m{
			"name":      nc.details.Name,
			"ips":       nc.details.Ips,
			"subnets":   nc.details.Subnets,
			"groups":    nc.details.Groups,
			"notBefore": nc.details.NotBefore,
			"notAfter":  nc.details.NotAfter,
			"publicKey": fmt.Sprintf("%x", nc.details.PublicKey),
			"isCa":      nc.details.IsCA,
			"issuer":    nc.details.Issuer,
			"curve":     nc.details.Curve.String(),
		},
		"fingerprint": fp,
		"signature":   fmt.Sprintf("%x", nc.Signature()),
	}
	return json.Marshal(jc)
}

// TODO:
func (nc *certificateV1) Copy() Certificate {
	//	r, err := nc.Marshal()
	//	if err != nil {
	//		//TODO
	//		return nil
	//	}
	//
	//	c, err := UnmarshalNebulaCertificate(r)
	//	return c
	return nc
}

//func (nc *certificateV1) Copy() *certificateV1 {
//	c := &certificateV1{
//		Details: detailsV1{
//			Name:           nc.Details.Name,
//			Groups:         make([]string, len(nc.Details.Groups)),
//			Ips:            make([]*net.IPNet, len(nc.Details.Ips)),
//			Subnets:        make([]*net.IPNet, len(nc.Details.Subnets)),
//			NotBefore:      nc.Details.NotBefore,
//			NotAfter:       nc.Details.NotAfter,
//			PublicKey:      make([]byte, len(nc.Details.PublicKey)),
//			IsCA:           nc.Details.IsCA,
//			Issuer:         nc.Details.Issuer,
//			InvertedGroups: make(map[string]struct{}, len(nc.Details.InvertedGroups)),
//		},
//		Signature: make([]byte, len(nc.Signature)),
//	}
//
//	copy(c.Signature, nc.Signature)
//	copy(c.Details.Groups, nc.Details.Groups)
//	copy(c.Details.PublicKey, nc.Details.PublicKey)
//
//	for i, p := range nc.Details.Ips {
//		c.Details.Ips[i] = &net.IPNet{
//			IP:   make(net.IP, len(p.IP)),
//			Mask: make(net.IPMask, len(p.Mask)),
//		}
//		copy(c.Details.Ips[i].IP, p.IP)
//		copy(c.Details.Ips[i].Mask, p.Mask)
//	}
//
//	for i, p := range nc.Details.Subnets {
//		c.Details.Subnets[i] = &net.IPNet{
//			IP:   make(net.IP, len(p.IP)),
//			Mask: make(net.IPMask, len(p.Mask)),
//		}
//		copy(c.Details.Subnets[i].IP, p.IP)
//		copy(c.Details.Subnets[i].Mask, p.Mask)
//	}
//
//	for g := range nc.Details.InvertedGroups {
//		c.Details.InvertedGroups[g] = struct{}{}
//	}
//
//	return c
//}

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
