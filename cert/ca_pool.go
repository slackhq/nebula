package cert

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type CAPool struct {
	CAs           map[string]*CachedCertificate
	certBlocklist map[string]struct{}
}

// NewCAPool creates a CAPool
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

// AddCAFromPEM verifies a Nebula CA certificate and adds it to the pool
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

// TODO:
func (ncp *CAPool) AddCA(c Certificate) error {
	if !c.IsCA() {
		return fmt.Errorf("%s: %w", c.Name(), ErrNotCA)
	}

	if !c.CheckSignature(c.PublicKey()) {
		return fmt.Errorf("%s: %w", c.Name(), ErrNotSelfSigned)
	}

	sum, err := c.Sha256Sum()
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

// TODO:
func (ncp *CAPool) IsBlocklisted(sha string) bool {
	if _, ok := ncp.certBlocklist[sha]; ok {
		return true
	}

	return false
}

// VerifyCertificate verifies the certificate is valid and is signed by a trusted CA in the pool.
// If the certificate is valid then the returned CachedCertificate can be used in subsequent verification attempts
// to increase performance.
func (ncp *CAPool) VerifyCertificate(now time.Time, c Certificate) (*CachedCertificate, error) {
	sha, err := c.Sha256Sum()
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
	if len(signerSha) > 0 {
		if signerSha != signer.ShaSum {
			return nil, ErrSignatureMismatch
		}
		return signer, nil
	}
	if !c.CheckSignature(signer.Certificate.PublicKey()) {
		return nil, ErrSignatureMismatch
	}

	err = c.CheckRootConstraints(signer.Certificate)
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
