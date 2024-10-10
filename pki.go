package nebula

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
)

type PKI struct {
	cs     atomic.Pointer[CertState]
	caPool atomic.Pointer[cert.CAPool]
	l      *logrus.Logger
}

type CertState struct {
	Certificate         cert.Certificate
	RawCertificate      []byte
	RawCertificateNoKey []byte
	PublicKey           []byte
	PrivateKey          []byte
	pkcs11Backed        bool
}

func NewPKIFromConfig(l *logrus.Logger, c *config.C) (*PKI, error) {
	pki := &PKI{l: l}
	err := pki.reload(c, true)
	if err != nil {
		return nil, err
	}

	c.RegisterReloadCallback(func(c *config.C) {
		rErr := pki.reload(c, false)
		if rErr != nil {
			util.LogWithContextIfNeeded("Failed to reload PKI from config", rErr, l)
		}
	})

	return pki, nil
}

func (p *PKI) GetCertState() *CertState {
	return p.cs.Load()
}

func (p *PKI) GetCAPool() *cert.CAPool {
	return p.caPool.Load()
}

func (p *PKI) reload(c *config.C, initial bool) error {
	err := p.reloadCert(c, initial)
	if err != nil {
		if initial {
			return err
		}
		err.Log(p.l)
	}

	err = p.reloadCAPool(c)
	if err != nil {
		if initial {
			return err
		}
		err.Log(p.l)
	}

	return nil
}

func (p *PKI) reloadCert(c *config.C, initial bool) *util.ContextualError {
	cs, err := newCertStateFromConfig(c)
	if err != nil {
		return util.NewContextualError("Could not load client cert", nil, err)
	}

	if !initial {
		//TODO: include check for mask equality as well

		// did IP in cert change? if so, don't set
		currentCert := p.cs.Load().Certificate
		oldIPs := currentCert.Networks()
		newIPs := cs.Certificate.Networks()
		if len(oldIPs) > 0 && len(newIPs) > 0 && oldIPs[0].String() != newIPs[0].String() {
			return util.NewContextualError(
				"Networks in new cert was different from old",
				m{"new_network": newIPs[0], "old_network": oldIPs[0]},
				nil,
			)
		}
	}

	p.cs.Store(cs)
	if initial {
		p.l.WithField("cert", cs.Certificate).Debug("Client nebula certificate")
	} else {
		p.l.WithField("cert", cs.Certificate).Info("Client cert refreshed from disk")
	}
	return nil
}

func (p *PKI) reloadCAPool(c *config.C) *util.ContextualError {
	caPool, err := loadCAPoolFromConfig(p.l, c)
	if err != nil {
		return util.NewContextualError("Failed to load ca from config", nil, err)
	}

	p.caPool.Store(caPool)
	p.l.WithField("fingerprints", caPool.GetFingerprints()).Debug("Trusted CA fingerprints")
	return nil
}

func newCertState(certificate cert.Certificate, pkcs11backed bool, privateKey []byte) (*CertState, error) {
	// Marshal the certificate to ensure it is valid
	rawCertificate, err := certificate.Marshal()
	if err != nil {
		return nil, fmt.Errorf("invalid nebula certificate on interface: %s", err)
	}

	publicKey := certificate.PublicKey()
	cs := &CertState{
		RawCertificate: rawCertificate,
		Certificate:    certificate,
		PrivateKey:     privateKey,
		PublicKey:      publicKey,
		pkcs11Backed:   pkcs11backed,
	}

	rawCertNoKey, err := cs.Certificate.MarshalForHandshakes()
	if err != nil {
		return nil, fmt.Errorf("error marshalling certificate no key: %s", err)
	}
	cs.RawCertificateNoKey = rawCertNoKey

	return cs, nil
}

func loadPrivateKey(privPathOrPEM string) (rawKey []byte, curve cert.Curve, isPkcs11 bool, err error) {
	var pemPrivateKey []byte
	if strings.Contains(privPathOrPEM, "-----BEGIN") {
		pemPrivateKey = []byte(privPathOrPEM)
		privPathOrPEM = "<inline>"
		rawKey, _, curve, err = cert.UnmarshalPrivateKeyFromPEM(pemPrivateKey)
		if err != nil {
			return nil, curve, false, fmt.Errorf("error while unmarshaling pki.key %s: %s", privPathOrPEM, err)
		}
	} else if strings.HasPrefix(privPathOrPEM, "pkcs11:") {
		rawKey = []byte(privPathOrPEM)
		return rawKey, cert.Curve_P256, true, nil
	} else {
		pemPrivateKey, err = os.ReadFile(privPathOrPEM)
		if err != nil {
			return nil, curve, false, fmt.Errorf("unable to read pki.key file %s: %s", privPathOrPEM, err)
		}
		rawKey, _, curve, err = cert.UnmarshalPrivateKeyFromPEM(pemPrivateKey)
		if err != nil {
			return nil, curve, false, fmt.Errorf("error while unmarshaling pki.key %s: %s", privPathOrPEM, err)
		}
	}

	return
}

func newCertStateFromConfig(c *config.C) (*CertState, error) {
	var err error

	privPathOrPEM := c.GetString("pki.key", "")
	if privPathOrPEM == "" {
		return nil, errors.New("no pki.key path or PEM data provided")
	}

	rawKey, curve, isPkcs11, err := loadPrivateKey(privPathOrPEM)
	if err != nil {
		return nil, err
	}

	var rawCert []byte

	pubPathOrPEM := c.GetString("pki.cert", "")
	if pubPathOrPEM == "" {
		return nil, errors.New("no pki.cert path or PEM data provided")
	}

	if strings.Contains(pubPathOrPEM, "-----BEGIN") {
		rawCert = []byte(pubPathOrPEM)
		pubPathOrPEM = "<inline>"

	} else {
		rawCert, err = os.ReadFile(pubPathOrPEM)
		if err != nil {
			return nil, fmt.Errorf("unable to read pki.cert file %s: %s", pubPathOrPEM, err)
		}
	}

	nebulaCert, _, err := cert.UnmarshalCertificateFromPEM(rawCert)
	if err != nil {
		return nil, fmt.Errorf("error while unmarshaling pki.cert %s: %s", pubPathOrPEM, err)
	}

	if nebulaCert.Expired(time.Now()) {
		return nil, fmt.Errorf("nebula certificate for this host is expired")
	}

	if len(nebulaCert.Networks()) == 0 {
		return nil, fmt.Errorf("no networks encoded in certificate")
	}

	if err = nebulaCert.VerifyPrivateKey(curve, rawKey); err != nil {
		return nil, fmt.Errorf("private key is not a pair with public key in nebula cert")
	}

	return newCertState(nebulaCert, isPkcs11, rawKey)
}

func loadCAPoolFromConfig(l *logrus.Logger, c *config.C) (*cert.CAPool, error) {
	var rawCA []byte
	var err error

	caPathOrPEM := c.GetString("pki.ca", "")
	if caPathOrPEM == "" {
		return nil, errors.New("no pki.ca path or PEM data provided")
	}

	if strings.Contains(caPathOrPEM, "-----BEGIN") {
		rawCA = []byte(caPathOrPEM)

	} else {
		rawCA, err = os.ReadFile(caPathOrPEM)
		if err != nil {
			return nil, fmt.Errorf("unable to read pki.ca file %s: %s", caPathOrPEM, err)
		}
	}

	caPool, err := cert.NewCAPoolFromPEM(rawCA)
	if errors.Is(err, cert.ErrExpired) {
		var expired int
		for _, crt := range caPool.CAs {
			if crt.Certificate.Expired(time.Now()) {
				expired++
				l.WithField("cert", crt).Warn("expired certificate present in CA pool")
			}
		}

		if expired >= len(caPool.CAs) {
			return nil, errors.New("no valid CA certificates present")
		}

	} else if err != nil {
		return nil, fmt.Errorf("error while adding CA certificate to CA trust store: %s", err)
	}

	for _, fp := range c.GetStringSlice("pki.blocklist", []string{}) {
		l.WithField("fingerprint", fp).Info("Blocklisting cert")
		caPool.BlocklistFingerprint(fp)
	}

	return caPool, nil
}
