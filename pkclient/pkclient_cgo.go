//go:build cgo && pkcs11

package pkclient

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

type PKClient struct {
	module     p11.Module
	session    p11.Session
	id         []byte
	label      []byte
	privKeyObj p11.Object
	pubKeyObj  p11.Object
}

type ecdsaSignature struct {
	R, S *big.Int
}

// New tries to open a session with the HSM, select the slot and login to it
func New(hsmPath string, slotId uint, pin string, id string, label string) (*PKClient, error) {
	module, err := p11.OpenModule(hsmPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load module library: %s", hsmPath)
	}

	slots, err := module.Slots()
	if err != nil {
		module.Destroy()
		return nil, err
	}

	// Try to open a session on the slot
	slotIdx := 0
	for i, slot := range slots {
		if slot.ID() == slotId {
			slotIdx = i
			break
		}
	}

	client := &PKClient{
		module: module,
		id:     []byte(id),
		label:  []byte(label),
	}

	client.session, err = slots[slotIdx].OpenWriteSession()
	if err != nil {
		module.Destroy()
		return nil, fmt.Errorf("failed to open session on slot %d", slotId)
	}

	if len(pin) != 0 {
		err = client.session.Login(pin)
		if err != nil {
			// ignore "already logged in"
			if !errors.Is(err, pkcs11.Error(256)) {
				_ = client.session.Close()
				return nil, fmt.Errorf("unable to login. error: %w", err)
			}
		}
	}

	// Make sure the hsm has a private key for deriving
	client.privKeyObj, err = client.findDeriveKey(client.id, client.label, true)
	if err != nil {
		_ = client.Close() //log out, close session, destroy module
		return nil, fmt.Errorf("failed to find private key for deriving: %w", err)
	}

	return client, nil
}

// Close cleans up properly and logs out
func (c *PKClient) Close() error {
	var err error = nil
	if c.session != nil {
		_ = c.session.Logout() //if logout fails, we still want to close
		err = c.session.Close()
	}

	c.module.Destroy()
	return err
}

// Try to find a suitable key on the hsm for key derivation
// parameter GET_PUB_KEY sets the search pattern for a public or private key
func (c *PKClient) findDeriveKey(id []byte, label []byte, private bool) (key p11.Object, err error) {
	keyClass := pkcs11.CKO_PRIVATE_KEY
	if !private {
		keyClass = pkcs11.CKO_PUBLIC_KEY
	}
	keyAttrs := []*pkcs11.Attribute{
		//todo, not all HSMs seem to report this, even if its true: pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, keyClass),
	}

	if id != nil && len(id) != 0 {
		keyAttrs = append(keyAttrs, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil && len(label) != 0 {
		keyAttrs = append(keyAttrs, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}

	return c.session.FindObject(keyAttrs)
}

func (c *PKClient) listDeriveKeys(id []byte, label []byte, private bool) {
	keyClass := pkcs11.CKO_PRIVATE_KEY
	if !private {
		keyClass = pkcs11.CKO_PUBLIC_KEY
	}
	keyAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, keyClass),
	}

	if id != nil && len(id) != 0 {
		keyAttrs = append(keyAttrs, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil && len(label) != 0 {
		keyAttrs = append(keyAttrs, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}

	objects, err := c.session.FindObjects(keyAttrs)
	if err != nil {
		return
	}

	for _, obj := range objects {
		l, err := obj.Label()
		log.Printf("%s, %v", l, err)
		a, err := obj.Attribute(pkcs11.CKA_DERIVE)
		log.Printf("DERIVE: %s %v, %v", l, a, err)
	}
}

// SignASN1 signs some data. Returns the ASN.1 encoded signature.
func (c *PKClient) SignASN1(data []byte) ([]byte, error) {
	mech := pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)
	sk := p11.PrivateKey(c.privKeyObj)
	rawSig, err := sk.Sign(*mech, data)
	if err != nil {
		return nil, err
	}

	// PKCS #11 Mechanisms v2.30:
	// "The signature octets correspond to the concatenation of the ECDSA values r and s,
	// both represented as an octet string of equal length of at most nLen with the most
	// significant byte first. If r and s have different octet length, the shorter of both
	// must be padded with leading zero octets such that both have the same octet length.
	// Loosely spoken, the first half of the signature is r and the second half is s."
	r := new(big.Int).SetBytes(rawSig[:len(rawSig)/2])
	s := new(big.Int).SetBytes(rawSig[len(rawSig)/2:])
	return asn1.Marshal(ecdsaSignature{r, s})
}

// DeriveNoise derives a shared secret using the input public key against the private key that was found during setup.
// Returns a fixed 32 byte array.
func (c *PKClient) DeriveNoise(peerPubKey []byte) ([]byte, error) {
	// Before we call derive, we need to have an array of attributes which specify the type of
	// key to be returned, in our case, it's the shared secret key, produced via deriving
	// This template pulled from OpenSC pkclient-tool.c line 4038
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, NoiseKeySize),
	}

	// Set up the parameters which include the peer's public key
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey)
	mech := pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, ecdhParams)
	sk := p11.PrivateKey(c.privKeyObj)

	tmpKey, err := sk.Derive(*mech, attrTemplate)
	if err != nil {
		return nil, err
	}
	if tmpKey == nil || len(tmpKey) == 0 {
		return nil, fmt.Errorf("got an empty secret key")
	}
	secret := make([]byte, NoiseKeySize)
	copy(secret[:], tmpKey[:NoiseKeySize])
	return secret, nil
}

func (c *PKClient) GetPubKey() ([]byte, error) {
	d, err := c.privKeyObj.Attribute(pkcs11.CKA_PUBLIC_KEY_INFO)
	if err != nil {
		return nil, err
	}
	if d != nil && len(d) > 0 {
		return formatPubkeyFromPublicKeyInfoAttr(d)
	}
	c.pubKeyObj, err = c.findDeriveKey(c.id, c.label, false)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 module gave us a nil CKA_PUBLIC_KEY_INFO, and looking up the public key also failed: %w", err)
	}
	d, err = c.pubKeyObj.Attribute(pkcs11.CKA_EC_POINT)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 module gave us a nil CKA_PUBLIC_KEY_INFO, and reading CKA_EC_POINT also failed: %w", err)
	}
	if d == nil || len(d) < 1 {
		return nil, fmt.Errorf("pkcs11 module gave us a nil or empty CKA_EC_POINT")
	}
	switch len(d) {
	case 65: //length of 0x04 + len(X) + len(Y)
		return d, nil
	case 67: //as above, DER-encoded IIRC?
		return d[2:], nil
	default:
		return nil, fmt.Errorf("unknown public key length: %d", len(d))
	}
}
