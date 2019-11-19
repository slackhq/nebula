package cert

import (
	"fmt"
	"strings"
	"time"
)

type NebulaCAPool struct {
	CAs           map[string]*NebulaCertificate
	certBlacklist map[string]struct{}
}

// NewCAPool creates a CAPool
func NewCAPool() *NebulaCAPool {
	ca := NebulaCAPool{
		CAs:           make(map[string]*NebulaCertificate),
		certBlacklist: make(map[string]struct{}),
	}

	return &ca
}

func NewCAPoolFromBytes(caPEMs []byte) (*NebulaCAPool, error) {
	pool := NewCAPool()
	var err error
	for {
		caPEMs, err = pool.AddCACertificate(caPEMs)
		if err != nil {
			return nil, err
		}
		if caPEMs == nil || len(caPEMs) == 0 || strings.TrimSpace(string(caPEMs)) == "" {
			break
		}
	}

	return pool, nil
}

// AddCACertificate verifies a Nebula CA certificate and adds it to the pool
// Only the first pem encoded object will be consumed, any remaining bytes are returned.
// Parsed certificates will be verified and must be a CA
func (ncp *NebulaCAPool) AddCACertificate(pemBytes []byte) ([]byte, error) {
	c, pemBytes, err := UnmarshalNebulaCertificateFromPEM(pemBytes)
	if err != nil {
		return pemBytes, err
	}

	if !c.Details.IsCA {
		return pemBytes, fmt.Errorf("provided certificate was not a CA; %s", c.Details.Name)
	}

	if !c.CheckSignature(c.Details.PublicKey) {
		return pemBytes, fmt.Errorf("provided certificate was not self signed; %s", c.Details.Name)
	}

	if c.Expired(time.Now()) {
		return pemBytes, fmt.Errorf("provided CA certificate is expired; %s", c.Details.Name)
	}

	sum, err := c.Sha256Sum()
	if err != nil {
		return pemBytes, fmt.Errorf("could not calculate shasum for provided CA; error: %s; %s", err, c.Details.Name)
	}

	ncp.CAs[sum] = c
	return pemBytes, nil
}

// BlacklistFingerprint adds a cert fingerprint to the blacklist
func (ncp *NebulaCAPool) BlacklistFingerprint(f string) {
	ncp.certBlacklist[f] = struct{}{}
}

// ResetCertBlacklist removes all previously blacklisted cert fingerprints
func (ncp *NebulaCAPool) ResetCertBlacklist() {
	ncp.certBlacklist = make(map[string]struct{})
}

// IsBlacklisted returns true if the fingerprint fails to generate or has been explicitly blacklisted
func (ncp *NebulaCAPool) IsBlacklisted(c *NebulaCertificate) bool {
	h, err := c.Sha256Sum()
	if err != nil {
		return true
	}

	if _, ok := ncp.certBlacklist[h]; ok {
		return true
	}

	return false
}

// GetCAForCert attempts to return the signing certificate for the provided certificate.
// No signature validation is performed
func (ncp *NebulaCAPool) GetCAForCert(c *NebulaCertificate) (*NebulaCertificate, error) {
	if c.Details.Issuer == "" {
		return nil, fmt.Errorf("no issuer in certificate")
	}

	signer, ok := ncp.CAs[c.Details.Issuer]
	if ok {
		return signer, nil
	}

	return nil, fmt.Errorf("could not find ca for the certificate")
}

// GetFingerprints returns an array of trusted CA fingerprints
func (ncp *NebulaCAPool) GetFingerprints() []string {
	fp := make([]string, len(ncp.CAs))

	i := 0
	for k := range ncp.CAs {
		fp[i] = k
		i++
	}

	return fp
}
