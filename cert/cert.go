package cert

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/proto"
)

const publicKeyLen = 32

const (
	CertBanner                       = "NEBULA CERTIFICATE"
	X25519PrivateKeyBanner           = "NEBULA X25519 PRIVATE KEY"
	X25519PublicKeyBanner            = "NEBULA X25519 PUBLIC KEY"
	EncryptedEd25519PrivateKeyBanner = "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
	Ed25519PrivateKeyBanner          = "NEBULA ED25519 PRIVATE KEY"
	Ed25519PublicKeyBanner           = "NEBULA ED25519 PUBLIC KEY"
)

type NebulaCertificate struct {
	Details   NebulaCertificateDetails
	Signature []byte
}

type NebulaCertificateDetails struct {
	Name      string
	Ips       []*net.IPNet
	Subnets   []*net.IPNet
	Groups    []string
	NotBefore time.Time
	NotAfter  time.Time
	PublicKey []byte
	IsCA      bool
	Issuer    string

	// Map of groups for faster lookup
	InvertedGroups map[string]struct{}
}

type NebulaEncryptedData struct {
	EncryptionMetadata NebulaEncryptionMetadata
	Ciphertext         []byte
}

type NebulaEncryptionMetadata struct {
	EncryptionAlgorithm string
	Argon2Parameters    Argon2Parameters
}

type m map[string]interface{}

// Returned if we try to unmarshal an encrypted private key without a passphrase
var ErrPrivateKeyEncrypted = errors.New("private key must be decrypted")

// UnmarshalNebulaCertificate will unmarshal a protobuf byte representation of a nebula cert
func UnmarshalNebulaCertificate(b []byte) (*NebulaCertificate, error) {
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

	nc := NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name:           rc.Details.Name,
			Groups:         make([]string, len(rc.Details.Groups)),
			Ips:            make([]*net.IPNet, len(rc.Details.Ips)/2),
			Subnets:        make([]*net.IPNet, len(rc.Details.Subnets)/2),
			NotBefore:      time.Unix(rc.Details.NotBefore, 0),
			NotAfter:       time.Unix(rc.Details.NotAfter, 0),
			PublicKey:      make([]byte, len(rc.Details.PublicKey)),
			IsCA:           rc.Details.IsCA,
			InvertedGroups: make(map[string]struct{}),
		},
		Signature: make([]byte, len(rc.Signature)),
	}

	copy(nc.Signature, rc.Signature)
	copy(nc.Details.Groups, rc.Details.Groups)
	nc.Details.Issuer = hex.EncodeToString(rc.Details.Issuer)

	if len(rc.Details.PublicKey) < publicKeyLen {
		return nil, fmt.Errorf("Public key was fewer than 32 bytes; %v", len(rc.Details.PublicKey))
	}
	copy(nc.Details.PublicKey, rc.Details.PublicKey)

	for i, rawIp := range rc.Details.Ips {
		if i%2 == 0 {
			nc.Details.Ips[i/2] = &net.IPNet{IP: int2ip(rawIp)}
		} else {
			nc.Details.Ips[i/2].Mask = net.IPMask(int2ip(rawIp))
		}
	}

	for i, rawIp := range rc.Details.Subnets {
		if i%2 == 0 {
			nc.Details.Subnets[i/2] = &net.IPNet{IP: int2ip(rawIp)}
		} else {
			nc.Details.Subnets[i/2].Mask = net.IPMask(int2ip(rawIp))
		}
	}

	for _, g := range rc.Details.Groups {
		nc.Details.InvertedGroups[g] = struct{}{}
	}

	return &nc, nil
}

// UnmarshalNebulaCertificateFromPEM will unmarshal the first pem block in a byte array, returning any non consumed data
// or an error on failure
func UnmarshalNebulaCertificateFromPEM(b []byte) (*NebulaCertificate, []byte, error) {
	p, r := pem.Decode(b)
	if p == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if p.Type != CertBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper nebula certificate banner")
	}
	nc, err := UnmarshalNebulaCertificate(p.Bytes)
	return nc, r, err
}

// MarshalX25519PrivateKey is a simple helper to PEM encode an X25519 private key
func MarshalX25519PrivateKey(b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: X25519PrivateKeyBanner, Bytes: b})
}

// MarshalEd25519PrivateKey is a simple helper to PEM encode an Ed25519 private key
func MarshalEd25519PrivateKey(key ed25519.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: Ed25519PrivateKeyBanner, Bytes: key})
}

// EncryptAndMarshalX25519PrivateKey is a simple helper to encrypt and PEM encode an X25519 private key
func EncryptAndMarshalEd25519PrivateKey(b []byte, passphrase []byte, kdfParams *Argon2Parameters) ([]byte, error) {
	ciphertext, err := aes256Encrypt(passphrase, kdfParams, b)
	if err != nil {
		return nil, err
	}

	b, err = proto.Marshal(&RawNebulaEncryptedData{
		EncryptionMetadata: &RawNebulaEncryptionMetadata{
			EncryptionAlgorithm: "AES-256-GCM",
			Argon2Parameters: &RawNebulaArgon2Parameters{
				Version:     kdfParams.version,
				Memory:      kdfParams.Memory,
				Parallelism: uint32(kdfParams.Parallelism),
				Iterations:  kdfParams.Iterations,
				Salt:        kdfParams.salt,
			},
		},
		Ciphertext: ciphertext,
	})

	return pem.EncodeToMemory(&pem.Block{Type: EncryptedEd25519PrivateKeyBanner, Bytes: b}), nil
}

// UnmarshalX25519PrivateKey will try to pem decode an X25519 private key, returning any other bytes b
// or an error on failure
func UnmarshalX25519PrivateKey(b []byte) ([]byte, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if k.Type != X25519PrivateKeyBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper nebula X25519 private key banner")
	}
	if len(k.Bytes) != publicKeyLen {
		return nil, r, fmt.Errorf("key was not 32 bytes, is invalid X25519 private key")
	}

	return k.Bytes, r, nil
}

// UnmarshalEd25519PrivateKey will try to pem decode an Ed25519 private key, returning any other bytes b
// or an error on failure
func UnmarshalEd25519PrivateKey(b []byte) (ed25519.PrivateKey, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}

	if k.Type == EncryptedEd25519PrivateKeyBanner {
		return nil, r, ErrPrivateKeyEncrypted
	} else if k.Type != Ed25519PrivateKeyBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper nebula Ed25519 private key banner")
	}

	if len(k.Bytes) != ed25519.PrivateKeySize {
		return nil, r, fmt.Errorf("key was not 64 bytes, is invalid ed25519 private key")
	}

	return k.Bytes, r, nil
}

// UnmarshalNebulaCertificate will unmarshal a protobuf byte representation of a nebula cert into its
// protobuf-generated struct.
func UnmarshalNebulaEncryptedData(b []byte) (*NebulaEncryptedData, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("nil byte array")
	}
	var rned RawNebulaEncryptedData
	err := proto.Unmarshal(b, &rned)
	if err != nil {
		return nil, err
	}

	if rned.EncryptionMetadata == nil {
		return nil, fmt.Errorf("encoded EncryptionMetadata was nil")
	}

	if rned.EncryptionMetadata.Argon2Parameters == nil {
		return nil, fmt.Errorf("encoded Argon2Parameters was nil")
	}

	params, err := unmarshalArgon2Parameters(rned.EncryptionMetadata.Argon2Parameters)
	if err != nil {
		return nil, err
	}

	ned := NebulaEncryptedData{
		EncryptionMetadata: NebulaEncryptionMetadata{
			EncryptionAlgorithm: rned.EncryptionMetadata.EncryptionAlgorithm,
			Argon2Parameters:    *params,
		},
		Ciphertext: rned.Ciphertext,
	}

	return &ned, nil
}

func unmarshalArgon2Parameters(params *RawNebulaArgon2Parameters) (*Argon2Parameters, error) {
	if params.Version < math.MinInt32 || params.Version > math.MaxInt32 {
		return nil, fmt.Errorf("Argon2Parameters Version must be at least %d and no more than %d", math.MinInt32, math.MaxInt32)
	}
	if params.Memory <= 0 || params.Memory > math.MaxUint32 {
		return nil, fmt.Errorf("Argon2Parameters Memory must be be greater than 0 and no more than %d KiB", uint32(math.MaxUint32))
	}
	if params.Parallelism <= 0 || params.Parallelism > math.MaxUint8 {
		return nil, fmt.Errorf("Argon2Parameters Parallelism must be be greater than 0 and no more than %d", math.MaxUint8)
	}
	if params.Iterations <= 0 || params.Iterations > math.MaxUint32 {
		return nil, fmt.Errorf("-argon-iterations must be be greater than 0 and no more than %d", uint32(math.MaxUint32))
	}

	return &Argon2Parameters{
		version:     rune(params.Version),
		Memory:      uint32(params.Memory),
		Parallelism: uint8(params.Parallelism),
		Iterations:  uint32(params.Iterations),
		salt:        params.Salt,
	}, nil

}

// DecryptAndUnmarshalEd25519PrivateKey will try to pem decode and decrypt an Ed25519 private key with
// the given passphrase, returning any other bytes b or an error on failure
func DecryptAndUnmarshalEd25519PrivateKey(passphrase, b []byte) (ed25519.PrivateKey, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}

	if k.Type != EncryptedEd25519PrivateKeyBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper nebula encrypted Ed25519 private key banner")
	}

	ned, err := UnmarshalNebulaEncryptedData(k.Bytes)
	if err != nil {
		return nil, r, err
	}

	var bytes []byte
	switch ned.EncryptionMetadata.EncryptionAlgorithm {
	case "AES-256-GCM":
		bytes, err = aes256Decrypt(passphrase, &ned.EncryptionMetadata.Argon2Parameters, ned.Ciphertext)
		if err != nil {
			return nil, r, err
		}
	default:
		return nil, r, fmt.Errorf("unsupported encryption algorithm: %s", ned.EncryptionMetadata.EncryptionAlgorithm)
	}

	if len(bytes) != ed25519.PrivateKeySize {
		return nil, r, fmt.Errorf("key was not 64 bytes, is invalid ed25519 private key")
	}

	return bytes, r, nil
}

// MarshalX25519PublicKey is a simple helper to PEM encode an X25519 public key
func MarshalX25519PublicKey(b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: X25519PublicKeyBanner, Bytes: b})
}

// MarshalEd25519PublicKey is a simple helper to PEM encode an Ed25519 public key
func MarshalEd25519PublicKey(key ed25519.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: Ed25519PublicKeyBanner, Bytes: key})
}

// UnmarshalX25519PublicKey will try to pem decode an X25519 public key, returning any other bytes b
// or an error on failure
func UnmarshalX25519PublicKey(b []byte) ([]byte, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if k.Type != X25519PublicKeyBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper nebula X25519 public key banner")
	}
	if len(k.Bytes) != publicKeyLen {
		return nil, r, fmt.Errorf("key was not 32 bytes, is invalid X25519 public key")
	}

	return k.Bytes, r, nil
}

// UnmarshalEd25519PublicKey will try to pem decode an Ed25519 public key, returning any other bytes b
// or an error on failure
func UnmarshalEd25519PublicKey(b []byte) (ed25519.PublicKey, []byte, error) {
	k, r := pem.Decode(b)
	if k == nil {
		return nil, r, fmt.Errorf("input did not contain a valid PEM encoded block")
	}
	if k.Type != Ed25519PublicKeyBanner {
		return nil, r, fmt.Errorf("bytes did not contain a proper nebula Ed25519 public key banner")
	}
	if len(k.Bytes) != ed25519.PublicKeySize {
		return nil, r, fmt.Errorf("key was not 32 bytes, is invalid ed25519 public key")
	}

	return k.Bytes, r, nil
}

// Sign signs a nebula cert with the provided private key
func (nc *NebulaCertificate) Sign(key ed25519.PrivateKey) error {
	b, err := proto.Marshal(nc.getRawDetails())
	if err != nil {
		return err
	}

	sig, err := key.Sign(rand.Reader, b, crypto.Hash(0))
	if err != nil {
		return err
	}
	nc.Signature = sig
	return nil
}

// CheckSignature verifies the signature against the provided public key
func (nc *NebulaCertificate) CheckSignature(key ed25519.PublicKey) bool {
	b, err := proto.Marshal(nc.getRawDetails())
	if err != nil {
		return false
	}
	return ed25519.Verify(key, b, nc.Signature)
}

// Expired will return true if the nebula cert is too young or too old compared to the provided time, otherwise false
func (nc *NebulaCertificate) Expired(t time.Time) bool {
	return nc.Details.NotBefore.After(t) || nc.Details.NotAfter.Before(t)
}

// Verify will ensure a certificate is good in all respects (expiry, group membership, signature, cert blocklist, etc)
func (nc *NebulaCertificate) Verify(t time.Time, ncp *NebulaCAPool) (bool, error) {
	if ncp.IsBlocklisted(nc) {
		return false, ErrBlockListed
	}

	signer, err := ncp.GetCAForCert(nc)
	if err != nil {
		return false, err
	}

	if signer.Expired(t) {
		return false, ErrRootExpired
	}

	if nc.Expired(t) {
		return false, ErrExpired
	}

	if !nc.CheckSignature(signer.Details.PublicKey) {
		return false, ErrSignatureMismatch
	}

	if err := nc.CheckRootConstrains(signer); err != nil {
		return false, err
	}

	return true, nil
}

// CheckRootConstrains returns an error if the certificate violates constraints set on the root (groups, ips, subnets)
func (nc *NebulaCertificate) CheckRootConstrains(signer *NebulaCertificate) error {
	// Make sure this cert wasn't valid before the root
	if signer.Details.NotAfter.Before(nc.Details.NotAfter) {
		return fmt.Errorf("certificate expires after signing certificate")
	}

	// Make sure this cert isn't valid after the root
	if signer.Details.NotBefore.After(nc.Details.NotBefore) {
		return fmt.Errorf("certificate is valid before the signing certificate")
	}

	// If the signer has a limited set of groups make sure the cert only contains a subset
	if len(signer.Details.InvertedGroups) > 0 {
		for _, g := range nc.Details.Groups {
			if _, ok := signer.Details.InvertedGroups[g]; !ok {
				return fmt.Errorf("certificate contained a group not present on the signing ca: %s", g)
			}
		}
	}

	// If the signer has a limited set of ip ranges to issue from make sure the cert only contains a subset
	if len(signer.Details.Ips) > 0 {
		for _, ip := range nc.Details.Ips {
			if !netMatch(ip, signer.Details.Ips) {
				return fmt.Errorf("certificate contained an ip assignment outside the limitations of the signing ca: %s", ip.String())
			}
		}
	}

	// If the signer has a limited set of subnet ranges to issue from make sure the cert only contains a subset
	if len(signer.Details.Subnets) > 0 {
		for _, subnet := range nc.Details.Subnets {
			if !netMatch(subnet, signer.Details.Subnets) {
				return fmt.Errorf("certificate contained a subnet assignment outside the limitations of the signing ca: %s", subnet)
			}
		}
	}

	return nil
}

// VerifyPrivateKey checks that the public key in the Nebula certificate and a supplied private key match
func (nc *NebulaCertificate) VerifyPrivateKey(key []byte) error {
	if nc.Details.IsCA {
		// the call to PublicKey below will panic slice bounds out of range otherwise
		if len(key) != ed25519.PrivateKeySize {
			return fmt.Errorf("key was not 64 bytes, is invalid ed25519 private key")
		}

		if !ed25519.PublicKey(nc.Details.PublicKey).Equal(ed25519.PrivateKey(key).Public()) {
			return fmt.Errorf("public key in cert and private key supplied don't match")
		}
		return nil
	}

	pub, err := curve25519.X25519(key, curve25519.Basepoint)
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, nc.Details.PublicKey) {
		return fmt.Errorf("public key in cert and private key supplied don't match")
	}

	return nil
}

// String will return a pretty printed representation of a nebula cert
func (nc *NebulaCertificate) String() string {
	if nc == nil {
		return "NebulaCertificate {}\n"
	}

	s := "NebulaCertificate {\n"
	s += "\tDetails {\n"
	s += fmt.Sprintf("\t\tName: %v\n", nc.Details.Name)

	if len(nc.Details.Ips) > 0 {
		s += "\t\tIps: [\n"
		for _, ip := range nc.Details.Ips {
			s += fmt.Sprintf("\t\t\t%v\n", ip.String())
		}
		s += "\t\t]\n"
	} else {
		s += "\t\tIps: []\n"
	}

	if len(nc.Details.Subnets) > 0 {
		s += "\t\tSubnets: [\n"
		for _, ip := range nc.Details.Subnets {
			s += fmt.Sprintf("\t\t\t%v\n", ip.String())
		}
		s += "\t\t]\n"
	} else {
		s += "\t\tSubnets: []\n"
	}

	if len(nc.Details.Groups) > 0 {
		s += "\t\tGroups: [\n"
		for _, g := range nc.Details.Groups {
			s += fmt.Sprintf("\t\t\t\"%v\"\n", g)
		}
		s += "\t\t]\n"
	} else {
		s += "\t\tGroups: []\n"
	}

	s += fmt.Sprintf("\t\tNot before: %v\n", nc.Details.NotBefore)
	s += fmt.Sprintf("\t\tNot After: %v\n", nc.Details.NotAfter)
	s += fmt.Sprintf("\t\tIs CA: %v\n", nc.Details.IsCA)
	s += fmt.Sprintf("\t\tIssuer: %s\n", nc.Details.Issuer)
	s += fmt.Sprintf("\t\tPublic key: %x\n", nc.Details.PublicKey)
	s += "\t}\n"
	fp, err := nc.Sha256Sum()
	if err == nil {
		s += fmt.Sprintf("\tFingerprint: %s\n", fp)
	}
	s += fmt.Sprintf("\tSignature: %x\n", nc.Signature)
	s += "}"

	return s
}

// getRawDetails marshals the raw details into protobuf ready struct
func (nc *NebulaCertificate) getRawDetails() *RawNebulaCertificateDetails {
	rd := &RawNebulaCertificateDetails{
		Name:      nc.Details.Name,
		Groups:    nc.Details.Groups,
		NotBefore: nc.Details.NotBefore.Unix(),
		NotAfter:  nc.Details.NotAfter.Unix(),
		PublicKey: make([]byte, len(nc.Details.PublicKey)),
		IsCA:      nc.Details.IsCA,
	}

	for _, ipNet := range nc.Details.Ips {
		rd.Ips = append(rd.Ips, ip2int(ipNet.IP), ip2int(ipNet.Mask))
	}

	for _, ipNet := range nc.Details.Subnets {
		rd.Subnets = append(rd.Subnets, ip2int(ipNet.IP), ip2int(ipNet.Mask))
	}

	copy(rd.PublicKey, nc.Details.PublicKey[:])

	// I know, this is terrible
	rd.Issuer, _ = hex.DecodeString(nc.Details.Issuer)

	return rd
}

// Marshal will marshal a nebula cert into a protobuf byte array
func (nc *NebulaCertificate) Marshal() ([]byte, error) {
	rc := RawNebulaCertificate{
		Details:   nc.getRawDetails(),
		Signature: nc.Signature,
	}

	return proto.Marshal(&rc)
}

// MarshalToPEM will marshal a nebula cert into a protobuf byte array and pem encode the result
func (nc *NebulaCertificate) MarshalToPEM() ([]byte, error) {
	b, err := nc.Marshal()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: CertBanner, Bytes: b}), nil
}

// Sha256Sum calculates a sha-256 sum of the marshaled certificate
func (nc *NebulaCertificate) Sha256Sum() (string, error) {
	b, err := nc.Marshal()
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (nc *NebulaCertificate) MarshalJSON() ([]byte, error) {
	toString := func(ips []*net.IPNet) []string {
		s := []string{}
		for _, ip := range ips {
			s = append(s, ip.String())
		}
		return s
	}

	fp, _ := nc.Sha256Sum()
	jc := m{
		"details": m{
			"name":      nc.Details.Name,
			"ips":       toString(nc.Details.Ips),
			"subnets":   toString(nc.Details.Subnets),
			"groups":    nc.Details.Groups,
			"notBefore": nc.Details.NotBefore,
			"notAfter":  nc.Details.NotAfter,
			"publicKey": fmt.Sprintf("%x", nc.Details.PublicKey),
			"isCa":      nc.Details.IsCA,
			"issuer":    nc.Details.Issuer,
		},
		"fingerprint": fp,
		"signature":   fmt.Sprintf("%x", nc.Signature),
	}
	return json.Marshal(jc)
}

//func (nc *NebulaCertificate) Copy() *NebulaCertificate {
//	r, err := nc.Marshal()
//	if err != nil {
//		//TODO
//		return nil
//	}
//
//	c, err := UnmarshalNebulaCertificate(r)
//	return c
//}

func (nc *NebulaCertificate) Copy() *NebulaCertificate {
	c := &NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name:           nc.Details.Name,
			Groups:         make([]string, len(nc.Details.Groups)),
			Ips:            make([]*net.IPNet, len(nc.Details.Ips)),
			Subnets:        make([]*net.IPNet, len(nc.Details.Subnets)),
			NotBefore:      nc.Details.NotBefore,
			NotAfter:       nc.Details.NotAfter,
			PublicKey:      make([]byte, len(nc.Details.PublicKey)),
			IsCA:           nc.Details.IsCA,
			Issuer:         nc.Details.Issuer,
			InvertedGroups: make(map[string]struct{}, len(nc.Details.InvertedGroups)),
		},
		Signature: make([]byte, len(nc.Signature)),
	}

	copy(c.Signature, nc.Signature)
	copy(c.Details.Groups, nc.Details.Groups)
	copy(c.Details.PublicKey, nc.Details.PublicKey)

	for i, p := range nc.Details.Ips {
		c.Details.Ips[i] = &net.IPNet{
			IP:   make(net.IP, len(p.IP)),
			Mask: make(net.IPMask, len(p.Mask)),
		}
		copy(c.Details.Ips[i].IP, p.IP)
		copy(c.Details.Ips[i].Mask, p.Mask)
	}

	for i, p := range nc.Details.Subnets {
		c.Details.Subnets[i] = &net.IPNet{
			IP:   make(net.IP, len(p.IP)),
			Mask: make(net.IPMask, len(p.Mask)),
		}
		copy(c.Details.Subnets[i].IP, p.IP)
		copy(c.Details.Subnets[i].Mask, p.Mask)
	}

	for g := range nc.Details.InvertedGroups {
		c.Details.InvertedGroups[g] = struct{}{}
	}

	return c
}

func netMatch(certIp *net.IPNet, rootIps []*net.IPNet) bool {
	for _, net := range rootIps {
		if net.Contains(certIp.IP) && maskContains(net.Mask, certIp.Mask) {
			return true
		}
	}

	return false
}

func maskContains(caMask, certMask net.IPMask) bool {
	caM := maskTo4(caMask)
	cM := maskTo4(certMask)
	// Make sure forcing to ipv4 didn't nuke us
	if caM == nil || cM == nil {
		return false
	}

	// Make sure the cert mask is not greater than the ca mask
	for i := 0; i < len(caMask); i++ {
		if caM[i] > cM[i] {
			return false
		}
	}

	return true
}

func maskTo4(ip net.IPMask) net.IPMask {
	if len(ip) == net.IPv4len {
		return ip
	}

	if len(ip) == net.IPv6len && isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff {
		return ip[12:16]
	}

	return nil
}

func isZeros(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
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
