package cert

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type NebulaCAPool struct {
	CAs           map[string]*NebulaCertificate
	certBlocklist map[string]struct{}
}

// NewCAPool creates a CAPool
func NewCAPool() *NebulaCAPool {
	ca := NebulaCAPool{
		CAs:           make(map[string]*NebulaCertificate),
		certBlocklist: make(map[string]struct{}),
	}

	return &ca
}

// NewCAPoolFromBytes will create a new CA pool from the provided
// input bytes, which must be a PEM-encoded set of nebula certificates.
// If the pool contains any expired certificates, an ErrExpired will be
// returned along with the pool. The caller must handle any such errors.
func NewCAPoolFromBytes(caPEMs []byte) (*NebulaCAPool, error) {
	pool := NewCAPool()
	var err error
	var expired bool
	for {
		caPEMs, err = pool.AddCACertificate(caPEMs)
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

// AddCACertificate verifies a Nebula CA certificate and adds it to the pool
// Only the first pem encoded object will be consumed, any remaining bytes are returned.
// Parsed certificates will be verified and must be a CA
func (ncp *NebulaCAPool) AddCACertificate(pemBytes []byte) ([]byte, error) {
	c, pemBytes, err := UnmarshalNebulaCertificateFromPEM(pemBytes)
	if err != nil {
		return pemBytes, err
	}

	if !c.Details.IsCA {
		return pemBytes, fmt.Errorf("%s: %w", c.Details.Name, ErrNotCA)
	}

	if !c.CheckSignature(c.Details.PublicKey) {
		return pemBytes, fmt.Errorf("%s: %w", c.Details.Name, ErrNotSelfSigned)
	}

	sum, err := c.Sha256Sum()
	if err != nil {
		return pemBytes, fmt.Errorf("could not calculate shasum for provided CA; error: %s; %s", err, c.Details.Name)
	}

	ncp.CAs[sum] = c
	if c.Expired(time.Now()) {
		return pemBytes, fmt.Errorf("%s: %w", c.Details.Name, ErrExpired)
	}

	return pemBytes, nil
}

// BlocklistFingerprint adds a cert fingerprint to the blocklist
func (ncp *NebulaCAPool) BlocklistFingerprint(f string) {
	ncp.certBlocklist[f] = struct{}{}
}

// ResetCertBlocklist removes all previously blocklisted cert fingerprints
func (ncp *NebulaCAPool) ResetCertBlocklist() {
	ncp.certBlocklist = make(map[string]struct{})
}

// IsBlocklisted returns true if the fingerprint fails to generate or has been explicitly blocklisted
func (ncp *NebulaCAPool) IsBlocklisted(c *NebulaCertificate) bool {
	return ncp.isBlocklisted(c, false)
}

// IsBlocklistedCached returns true if the fingerprint fails to generate or has been explicitly blocklisted.
// This is safe to use if the passed-in NebulaCertificate is never modified after creation.
func (ncp *NebulaCAPool) IsBlocklistedCached(c *NebulaCertificate) bool {
	return ncp.isBlocklisted(c, true)
}

// isBlocklisted returns true if the fingerprint fails to generate or has been explicitly blocklisted.
// If useCache is true, a cache is used to avoid unnecessary memory allocation.
func (ncp *NebulaCAPool) isBlocklisted(c *NebulaCertificate, useCache bool) bool {
	var h string
	var err error
	if useCache {
		var err error
		h, err = c.Sha256SumCached()
		if err != nil {
			return true
		}
	} else {
		h, err = c.Sha256Sum()
		if err != nil {
			return true
		}
	}

	if _, ok := ncp.certBlocklist[h]; ok {
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
