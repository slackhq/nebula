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
// Specific errors from the inner call to pool.AddCACertificate can be
// ignored (tested with errors.Is), any certificates that generate an
// ignored error will NOT be present in the returned pool.
func NewCAPoolFromBytes(caPEMs []byte, ignore ...error) (*NebulaCAPool, error) {
	pool := NewCAPool()
	var err error
	for {
		caPEMs, err = pool.AddCACertificate(caPEMs)
		if err != nil {
			ignored := false
			for _, e := range ignore {
				if errors.Is(err, e) {
					ignored = true
					break
				}
			}
			if !ignored {
				return nil, err
			}
		}
		if len(caPEMs) == 0 || strings.TrimSpace(string(caPEMs)) == "" {
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
		return pemBytes, fmt.Errorf("%s: %w", c.Details.Name, ErrNotCA)
	}

	if !c.CheckSignature(c.Details.PublicKey) {
		return pemBytes, fmt.Errorf("%s: %w", c.Details.Name, ErrNotSelfSigned)
	}

	if c.Expired(time.Now()) {
		return pemBytes, fmt.Errorf("%s: %w", c.Details.Name, ErrExpired)
	}

	sum, err := c.Sha256Sum()
	if err != nil {
		return pemBytes, fmt.Errorf("could not calculate shasum for provided CA; error: %s; %s", err, c.Details.Name)
	}

	ncp.CAs[sum] = c
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
	h, err := c.Sha256Sum()
	if err != nil {
		return true
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
