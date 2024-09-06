package cert

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/pkclient"
)

type TBSCertificate struct {
	Version        Version
	Name           string
	Networks       []netip.Prefix
	UnsafeNetworks []netip.Prefix
	Groups         []string
	IsCA           bool
	NotBefore      time.Time
	NotAfter       time.Time
	PublicKey      []byte
	Curve          Curve
	issuer         string
}

// TODO:
func (t *TBSCertificate) Sign(signer Certificate, curve Curve, key []byte) (Certificate, error) {
	return t.sign(signer, curve, key, nil)
}

func (t *TBSCertificate) SignPkcs11(signer Certificate, curve Curve, client *pkclient.PKClient) (Certificate, error) {
	if curve != Curve_P256 {
		return nil, fmt.Errorf("only P256 is supported by PKCS#11")
	}

	return t.sign(signer, curve, nil, client)
}

func (t *TBSCertificate) sign(signer Certificate, curve Curve, key []byte, client *pkclient.PKClient) (Certificate, error) {
	if curve != t.Curve {
		return nil, fmt.Errorf("curve in cert and private key supplied don't match")
	}

	//TODO: signer should assert its constraints on the TBSCertificate, once you do nebula-cert sign needs to not double do it
	if signer != nil {
		if t.IsCA {
			return nil, fmt.Errorf("can not sign a CA certificate with another")
		}
		issuer, err := signer.Sha256Sum()
		if err != nil {
			return nil, fmt.Errorf("error computing issuer: %v", err)
		}
		t.issuer = issuer
	} else {
		if !t.IsCA {
			return nil, fmt.Errorf("self signed certificates must have IsCA set to true")
		}
	}

	switch t.Version {
	case Version1:
		return signV1(t, curve, key, client)
	default:
		return nil, fmt.Errorf("unknown cert version %d", t.Version)
	}
}
