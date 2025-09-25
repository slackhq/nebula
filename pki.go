package nebula

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gaissmai/bart"
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
	v1Cert           cert.Certificate
	v1HandshakeBytes []byte

	v2Cert           cert.Certificate
	v2HandshakeBytes []byte

	initiatingVersion cert.Version
	privateKey        []byte
	pkcs11Backed      bool
	cipher            string

	myVpnNetworks            []netip.Prefix
	myVpnNetworksTable       *bart.Lite
	myVpnAddrs               []netip.Addr
	myVpnAddrsTable          *bart.Lite
	myVpnBroadcastAddrsTable *bart.Lite
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

func (p *PKI) GetCAPool() *cert.CAPool {
	return p.caPool.Load()
}

func (p *PKI) getCertState() *CertState {
	return p.cs.Load()
}

func (p *PKI) reload(c *config.C, initial bool) error {
	err := p.loadCerts(c, initial)
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

func checkCertReload(oldCert, newCert cert.Certificate) error {
	//changing the IPs or curve of existing certs is forbidden
	if !slices.Equal(oldCert.Networks(), newCert.Networks()) {
		return util.NewContextualError("Networks in new cert was different from old", m{"new_networks": newCert.Networks(), "old_networks": oldCert.Networks()}, nil)
	}

	if oldCert.Curve() != newCert.Curve() {
		return util.NewContextualError("Curve in new cert was different from old", m{"new_curve": newCert.Curve(), "old_curve": oldCert.Curve()}, nil)
	}
	return nil
}

func checkCertV1Reload(currentState *CertState, newState *CertState) error {
	if newState.v1Cert == nil {
		return nil //removing a V1 cert is always acceptable
	}
	if currentState.v1Cert == nil {
		return nil //going from no-v1-cert to has-a-v1-cert is also always okay
	}
	return checkCertReload(currentState.v1Cert, newState.v1Cert)
}

func checkCertV2Reload(currentState *CertState, newState *CertState) error {
	if currentState.v2Cert == nil {
		return nil //adding a v2 cert is always okay, as long as it doesn't conflict with old-v1?
	}

	if newState.v2Cert == nil {
		//removing a v2 cert. Make sure our networks are identical to V1, so we don't orphan vpnaddrs:
		if !slices.Equal(currentState.v2Cert.Networks(), newState.v1Cert.Networks()) {
			return util.NewContextualError(
				"Removing a V2 cert is not permitted unless it has identical networks to the new V1 cert",
				m{"new_networks": newState.v1Cert.Networks(), "old_networks": currentState.v2Cert.Networks()},
				nil)
		}
		return nil
	}

	return checkCertReload(currentState.v2Cert, newState.v2Cert)
}

func (p *PKI) reloadCerts(newState *CertState) *util.ContextualError {
	currentState := p.cs.Load()

	// Cipher cant be hot swapped so just leave it at what it was before
	newState.cipher = currentState.cipher
	if newState.v1Cert == nil && newState.v2Cert == nil {
		return util.NewContextualError("Impossible! v1Cert and v2Cert cannot both be nil", m{}, nil)
	}

	err := checkCertV1Reload(currentState, newState)
	if err != nil {
		return util.NewContextualError("Cert V1 reload check failed", m{}, err)
	}
	err = checkCertV2Reload(currentState, newState)
	if err != nil {
		return util.NewContextualError("Cert V2 reload check failed", m{}, err)
	}

	// cross check vpnaddrs on certstate objects too, to handle removing v1 and adding v2
	if slices.Equal(newState.myVpnNetworks, currentState.myVpnNetworks) {
		return util.NewContextualError("VPN address change not permitted",
			m{"new_networks": newState.myVpnNetworks, "old_networks": currentState.myVpnNetworks}, nil)
	}
	if newState.GetDefaultCertificate().Curve() != currentState.GetDefaultCertificate().Curve() {
		return util.NewContextualError(
			"Curve in new cert was different differs across cert versions",
			m{
				"new_curve": newState.GetDefaultCertificate().Curve(),
				"old_curve": currentState.GetDefaultCertificate().Curve(),
			}, nil)
	}

	return nil
}

func (p *PKI) loadCerts(c *config.C, initial bool) *util.ContextualError {
	newState, err := newCertStateFromConfig(c)
	if err != nil {
		return util.NewContextualError("Could not load client cert", nil, err)
	}

	if !initial {
		err := p.reloadCerts(newState)
		if err != nil {
			return err
		}
	} else {
		newState.cipher = c.GetString("cipher", "aes")
		//TODO: this sucks and we should make it not a global
		switch newState.cipher {
		case "aes":
			noiseEndianness = binary.BigEndian
		case "chachapoly":
			noiseEndianness = binary.LittleEndian
		default:
			return util.NewContextualError(
				"unknown cipher",
				m{"cipher": newState.cipher},
				nil,
			)
		}
	}

	p.cs.Store(newState)

	if initial {
		p.l.WithField("cert", newState).Debug("Client nebula certificate(s)")
	} else {
		p.l.WithField("cert", newState).Info("Client certificate(s) refreshed from disk")
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

func (cs *CertState) GetDefaultCertificate() cert.Certificate {
	c := cs.getCertificate(cs.initiatingVersion)
	if c == nil {
		panic("No default certificate found")
	}
	return c
}

func (cs *CertState) getCertificate(v cert.Version) cert.Certificate {
	switch v {
	case cert.Version1:
		return cs.v1Cert
	case cert.Version2:
		return cs.v2Cert
	}

	return nil
}

// getHandshakeBytes returns the cached bytes to be used in a handshake message for the requested version.
// Callers must check if the return []byte is nil.
func (cs *CertState) getHandshakeBytes(v cert.Version) []byte {
	switch v {
	case cert.Version1:
		return cs.v1HandshakeBytes
	case cert.Version2:
		return cs.v2HandshakeBytes
	default:
		return nil
	}
}

func (cs *CertState) String() string {
	b, err := cs.MarshalJSON()
	if err != nil {
		return fmt.Sprintf("error marshaling certificate state: %v", err)
	}
	return string(b)
}

func (cs *CertState) MarshalJSON() ([]byte, error) {
	msg := []json.RawMessage{}
	if cs.v1Cert != nil {
		b, err := cs.v1Cert.MarshalJSON()
		if err != nil {
			return nil, err
		}
		msg = append(msg, b)
	}

	if cs.v2Cert != nil {
		b, err := cs.v2Cert.MarshalJSON()
		if err != nil {
			return nil, err
		}
		msg = append(msg, b)
	}

	return json.Marshal(msg)
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

	var crt, v1, v2 cert.Certificate
	for {
		// Load the certificate
		crt, rawCert, err = loadCertificate(rawCert)
		if err != nil {
			return nil, err
		}

		switch crt.Version() {
		case cert.Version1:
			if v1 != nil {
				return nil, fmt.Errorf("v1 certificate already found in pki.cert")
			}
			v1 = crt
		case cert.Version2:
			if v2 != nil {
				return nil, fmt.Errorf("v2 certificate already found in pki.cert")
			}
			v2 = crt
		default:
			return nil, fmt.Errorf("unknown certificate version %v", crt.Version())
		}

		if len(rawCert) == 0 || strings.TrimSpace(string(rawCert)) == "" {
			break
		}
	}

	if v1 == nil && v2 == nil {
		return nil, errors.New("no certificates found in pki.cert")
	}

	useInitiatingVersion := uint32(1)
	if v1 == nil {
		// The only condition that requires v2 as the default is if only a v2 certificate is present
		// We do this to avoid having to configure it specifically in the config file
		useInitiatingVersion = 2
	}

	rawInitiatingVersion := c.GetUint32("pki.initiating_version", useInitiatingVersion)
	var initiatingVersion cert.Version
	switch rawInitiatingVersion {
	case 0:
		//TODO
	case 1:
		if v1 == nil {
			return nil, fmt.Errorf("can not use pki.initiating_version 1 without a v1 certificate in pki.cert")
		}
		initiatingVersion = cert.Version1
	case 2:
		if v2 == nil {
			return nil, fmt.Errorf("can not use pki.initiating_version 2 without a v2 certificate in pki.cert")
		}
		initiatingVersion = cert.Version2
	default:
		return nil, fmt.Errorf("unknown pki.initiating_version: %v", rawInitiatingVersion)
	}

	return newCertState(initiatingVersion, v1, v2, isPkcs11, curve, rawKey)
}

func newCertState(dv cert.Version, v1, v2 cert.Certificate, pkcs11backed bool, privateKeyCurve cert.Curve, privateKey []byte) (*CertState, error) {
	cs := CertState{
		privateKey:               privateKey,
		pkcs11Backed:             pkcs11backed,
		myVpnNetworksTable:       new(bart.Lite),
		myVpnAddrsTable:          new(bart.Lite),
		myVpnBroadcastAddrsTable: new(bart.Lite),
	}

	if v1 != nil && v2 != nil {
		if !slices.Equal(v1.PublicKey(), v2.PublicKey()) {
			return nil, util.NewContextualError("v1 and v2 public keys are not the same, ignoring", nil, nil)
		}

		if v1.Curve() != v2.Curve() {
			return nil, util.NewContextualError("v1 and v2 curve are not the same, ignoring", nil, nil)
		}

		if v1.Networks()[0] != v2.Networks()[0] {
			return nil, util.NewContextualError("v1 and v2 networks are not the same", nil, nil)
		}

		cs.initiatingVersion = dv
	}

	if v1 != nil {
		if pkcs11backed {
			//NOTE: We do not currently have a method to verify a public private key pair when the private key is in an hsm
		} else {
			if err := v1.VerifyPrivateKey(privateKeyCurve, privateKey); err != nil {
				return nil, fmt.Errorf("private key is not a pair with public key in nebula cert")
			}
		}

		v1hs, err := v1.MarshalForHandshakes()
		if err != nil {
			return nil, fmt.Errorf("error marshalling certificate for handshake: %w", err)
		}
		cs.v1Cert = v1
		cs.v1HandshakeBytes = v1hs

		if cs.initiatingVersion == 0 {
			cs.initiatingVersion = cert.Version1
		}
	}

	if v2 != nil {
		if pkcs11backed {
			//NOTE: We do not currently have a method to verify a public private key pair when the private key is in an hsm
		} else {
			if err := v2.VerifyPrivateKey(privateKeyCurve, privateKey); err != nil {
				return nil, fmt.Errorf("private key is not a pair with public key in nebula cert")
			}
		}

		v2hs, err := v2.MarshalForHandshakes()
		if err != nil {
			return nil, fmt.Errorf("error marshalling certificate for handshake: %w", err)
		}
		cs.v2Cert = v2
		cs.v2HandshakeBytes = v2hs

		if cs.initiatingVersion == 0 {
			cs.initiatingVersion = cert.Version2
		}
	}

	var crt cert.Certificate
	crt = cs.getCertificate(cert.Version2)
	if crt == nil {
		// v2 certificates are a superset, only look at v1 if its all we have
		crt = cs.getCertificate(cert.Version1)
	}

	for _, network := range crt.Networks() {
		cs.myVpnNetworks = append(cs.myVpnNetworks, network)
		cs.myVpnNetworksTable.Insert(network)

		cs.myVpnAddrs = append(cs.myVpnAddrs, network.Addr())
		cs.myVpnAddrsTable.Insert(netip.PrefixFrom(network.Addr(), network.Addr().BitLen()))

		if network.Addr().Is4() {
			addr := network.Masked().Addr().As4()
			mask := net.CIDRMask(network.Bits(), network.Addr().BitLen())
			binary.BigEndian.PutUint32(addr[:], binary.BigEndian.Uint32(addr[:])|^binary.BigEndian.Uint32(mask))
			cs.myVpnBroadcastAddrsTable.Insert(netip.PrefixFrom(netip.AddrFrom4(addr), network.Addr().BitLen()))
		}
	}

	return &cs, nil
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

func loadCertificate(b []byte) (cert.Certificate, []byte, error) {
	c, b, err := cert.UnmarshalCertificateFromPEM(b)
	if err != nil {
		return nil, b, fmt.Errorf("error while unmarshaling pki.cert: %w", err)
	}

	if c.Expired(time.Now()) {
		return nil, b, fmt.Errorf("nebula certificate for this host is expired")
	}

	if len(c.Networks()) == 0 {
		return nil, b, fmt.Errorf("no networks encoded in certificate")
	}

	if c.IsCA() {
		return nil, b, fmt.Errorf("host certificate is a CA certificate")
	}

	return c, b, nil
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
