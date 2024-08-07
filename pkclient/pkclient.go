package pkclient

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"io"
	"strconv"

	"github.com/stefanberger/go-pkcs11uri"
)

type Client interface {
	io.Closer
	GetPubKey() ([]byte, error)
	DeriveNoise(peerPubKey []byte) ([]byte, error)
	Test() error
}

const NoiseKeySize = 32

func FromUrl(pkurl string) (*PKClient, error) {
	uri := pkcs11uri.New()
	uri.SetAllowAnyModule(true) //todo
	err := uri.Parse(pkurl)
	if err != nil {
		return nil, err
	}

	module, err := uri.GetModule()
	if err != nil {
		return nil, err
	}

	slotid := 0
	slot, ok := uri.GetPathAttribute("slot-id", false)
	if !ok {
		slotid = 0
	} else {
		slotid, err = strconv.Atoi(slot)
		if err != nil {
			return nil, err
		}
	}

	pin, _ := uri.GetPIN()
	id, _ := uri.GetPathAttribute("id", false)
	label, _ := uri.GetPathAttribute("object", false)

	return New(module, uint(slotid), pin, id, label)
}

func ecKeyToArray(key *ecdsa.PublicKey) []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	return append([]byte{0x04}, append(x, y...)...)
}

func formatPubkeyFromPublicKeyInfoAttr(d []byte) ([]byte, error) {
	e, err := x509.ParsePKIXPublicKey(d)
	if err != nil {
		return nil, err
	}
	switch t := e.(type) {
	case *ecdsa.PublicKey:
		return ecKeyToArray(e.(*ecdsa.PublicKey)), nil
	default:
		return nil, fmt.Errorf("unknown public key type: %T", t)
	}
}

func (c *PKClient) Test() error {
	pub, err := c.GetPubKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}
	out, err := c.DeriveNoise(pub) //do an ECDH with ourselves as a quick test
	if err != nil {
		return err
	}
	if len(out) != NoiseKeySize {
		return fmt.Errorf("got a key of %d bytes, expected %d", len(out), NoiseKeySize)
	}
	return nil
}
