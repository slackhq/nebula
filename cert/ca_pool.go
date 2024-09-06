package cert

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type CAPool struct {
	CAs           map[string]*CachedCertificate
	certBlocklist map[string]struct{}
}

// NewCAPool creates an empty CAPool
func NewCAPool() *CAPool {
	ca := CAPool{
		CAs:           make(map[string]*CachedCertificate),
		certBlocklist: make(map[string]struct{}),
	}

	return &ca
}

// NewCAPoolFromPEM will create a new CA pool from the provided
// input bytes, which must be a PEM-encoded set of nebula certificates.
// If the pool contains any expired certificates, an ErrExpired will be
// returned along with the pool. The caller must handle any such errors.
func NewCAPoolFromPEM(caPEMs []byte) (*CAPool, error) {
	pool := NewCAPool()
	var err error
	var expired bool
	for {
		caPEMs, err = pool.AddCAFromPEM(caPEMs)
		if errors.Is(err, ErrExpired) {
			expired = true
			err = nil
		}
		if err != nil {
			return nil, err
		}
		if len(caPEMs) == 0 || strings.TrimSpace(string(caPEMs)) == "" {
			break
		}
	}

	if expired {
		return pool, ErrExpired
	}

	return pool, nil
}

// AddCAFromPEM verifies a Nebula CA certificate and adds it to the pool.
// Only the first pem encoded object will be consumed, any remaining bytes are returned.
// Parsed certificates will be verified and must be a CA
func (ncp *CAPool) AddCAFromPEM(pemBytes []byte) ([]byte, error) {
	c, pemBytes, err := UnmarshalCertificateFromPEM(pemBytes)
	if err != nil {
		return pemBytes, err
	}

	err = ncp.AddCA(c)
	if err != nil {
		return pemBytes, err
	}

	return pemBytes, nil
}

// AddCA verifies a Nebula CA certificate and adds it to the pool.
func (ncp *CAPool) AddCA(c Certificate) error {
	if !c.IsCA() {
		return fmt.Errorf("%s: %w", c.Name(), ErrNotCA)
	}

	if !c.CheckSignature(c.PublicKey()) {
		return fmt.Errorf("%s: %w", c.Name(), ErrNotSelfSigned)
	}

	sum, err := c.Fingerprint()
	if err != nil {
		return fmt.Errorf("could not calculate shasum for provided CA; error: %s; %s", err, c.Name())
	}

	cc := &CachedCertificate{
		Certificate:    c,
		ShaSum:         sum,
		InvertedGroups: make(map[string]struct{}),
	}

	for _, g := range c.Groups() {
		cc.InvertedGroups[g] = struct{}{}
	}

	ncp.CAs[sum] = cc

	if c.Expired(time.Now()) {
		return fmt.Errorf("%s: %w", c.Name(), ErrExpired)
	}

	return nil
}

// BlocklistFingerprint adds a cert fingerprint to the blocklist
func (ncp *CAPool) BlocklistFingerprint(f string) {
	ncp.certBlocklist[f] = struct{}{}
}

// ResetCertBlocklist removes all previously blocklisted cert fingerprints
func (ncp *CAPool) ResetCertBlocklist() {
	ncp.certBlocklist = make(map[string]struct{})
}

// IsBlocklisted tests the provided fingerprint against the pools blocklist.
// Returns true if the fingerprint is blocked.
func (ncp *CAPool) IsBlocklisted(fingerprint string) bool {
	if _, ok := ncp.certBlocklist[fingerprint]; ok {
		return true
	}

	return false
}

// VerifyCertificate verifies the certificate is valid and is signed by a trusted CA in the pool.
// If the certificate is valid then the returned CachedCertificate can be used in subsequent verification attempts
// to increase performance.
func (ncp *CAPool) VerifyCertificate(now time.Time, c Certificate) (*CachedCertificate, error) {
	if c == nil {
		return nil, fmt.Errorf("no certificate")
	}
	sha, err := c.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("could not calculate shasum to verify: %w", err)
	}

	signer, err := ncp.verify(c, now, sha, "")
	if err != nil {
		return nil, err
	}

	cc := CachedCertificate{
		Certificate:    c,
		InvertedGroups: make(map[string]struct{}),
		ShaSum:         sha,
		signerShaSum:   signer.ShaSum,
	}

	for _, g := range c.Groups() {
		cc.InvertedGroups[g] = struct{}{}
	}

	return &cc, nil
}

// VerifyCachedCertificate is the same as VerifyCertificate other than it operates on a pre-verified structure and
// is a cheaper operation to perform as a result.
func (ncp *CAPool) VerifyCachedCertificate(now time.Time, c *CachedCertificate) error {
	_, err := ncp.verify(c.Certificate, now, c.ShaSum, c.signerShaSum)
	return err
}

func (ncp *CAPool) verify(c Certificate, now time.Time, certSha string, signerSha string) (*CachedCertificate, error) {
	if ncp.IsBlocklisted(certSha) {
		return nil, ErrBlockListed
	}

	signer, err := ncp.GetCAForCert(c)
	if err != nil {
		return nil, err
	}

	if signer.Certificate.Expired(now) {
		return nil, ErrRootExpired
	}

	if c.Expired(now) {
		return nil, ErrExpired
	}

	// If we are checking a cached certificate then we can bail early here
	// Either the root is no longer trusted or everything is fine
	//TODO: this is slightly different than v1.9.3 and earlier where we were matching the public key
	// The reason to switch is that the public key can be reused and the constraints in the ca can change
	// but there may be history here, double check
	if len(signerSha) > 0 {
		if signerSha != signer.ShaSum {
			return nil, ErrSignatureMismatch
		}
		return signer, nil
	}
	if !c.CheckSignature(signer.Certificate.PublicKey()) {
		return nil, ErrSignatureMismatch
	}

	err = CheckCAConstraints(signer.Certificate, c)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// GetCAForCert attempts to return the signing certificate for the provided certificate.
// No signature validation is performed
func (ncp *CAPool) GetCAForCert(c Certificate) (*CachedCertificate, error) {
	if c.Issuer() == "" {
		return nil, fmt.Errorf("no issuer in certificate")
	}

	signer, ok := ncp.CAs[c.Issuer()]
	if ok {
		return signer, nil
	}

	return nil, fmt.Errorf("could not find ca for the certificate")
}

// GetFingerprints returns an array of trusted CA fingerprints
func (ncp *CAPool) GetFingerprints() []string {
	fp := make([]string, len(ncp.CAs))

	i := 0
	for k := range ncp.CAs {
		fp[i] = k
		i++
	}

	return fp
}

// CheckCAConstraints returns an error if the sub certificate violates constraints present in the signer certificate.
func CheckCAConstraints(signer Certificate, sub Certificate) error {
	return checkCAConstraints(signer, sub.NotBefore(), sub.NotAfter(), sub.Groups(), sub.Networks(), sub.UnsafeNetworks())
}

// checkCAConstraints is a very generic function allowing both Certificates and TBSCertificates to be tested.
func checkCAConstraints(signer Certificate, notBefore, notAfter time.Time, groups []string, networks, unsafeNetworks []netip.Prefix) error {
	// Make sure this cert wasn't valid before the root
	if notAfter.After(signer.NotAfter()) {
		return fmt.Errorf("certificate expires after signing certificate")
	}

	// Make sure this cert isn't valid after the root
	if notBefore.Before(signer.NotBefore()) {
		return fmt.Errorf("certificate is valid before the signing certificate")
	}

	// If the signer has a limited set of groups make sure the cert only contains a subset
	signerGroups := signer.Groups()
	if len(signerGroups) > 0 {
		for _, g := range groups {
			if !slices.Contains(signerGroups, g) {
				//TODO: since we no longer pre-compute the inverted groups then this is kind of slow
				return fmt.Errorf("certificate contained a group not present on the signing ca: %s", g)
			}
		}
	}

	// If the signer has a limited set of ip ranges to issue from make sure the cert only contains a subset
	signingNetworks := signer.Networks()
	if len(signingNetworks) > 0 {
		for _, subNetwork := range networks {
			found := false
			for _, signingNetwork := range signingNetworks {
				if signingNetwork.Contains(subNetwork.Addr()) && signingNetwork.Bits() <= subNetwork.Bits() {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("certificate contained an ip assignment outside the limitations of the signing ca: %s", subNetwork.String())
			}
		}
	}

	// If the signer has a limited set of subnet ranges to issue from make sure the cert only contains a subset
	signingUnsafeNetworks := signer.UnsafeNetworks()
	if len(signingUnsafeNetworks) > 0 {
		for _, subUnsafeNetwork := range unsafeNetworks {
			found := false
			for _, caNetwork := range signingUnsafeNetworks {
				if caNetwork.Contains(subUnsafeNetwork.Addr()) && caNetwork.Bits() <= subUnsafeNetwork.Bits() {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("certificate contained a subnet assignment outside the limitations of the signing ca: %s", subUnsafeNetwork.String())
			}
		}
	}

	return nil
}
