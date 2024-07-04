//go:build !cgo || !pkcs11

package pkclient

import "errors"

type PKClient struct {
}

var notImplemented = errors.New("not implemented")

func New(hsmPath string, slotId uint, pin string, id string, label string) (*PKClient, error) {
	return nil, notImplemented
}

func (c *PKClient) Close() error {
	return nil
}

func (c *PKClient) SignASN1(data []byte) ([]byte, error) {
	return nil, notImplemented
}

func (c *PKClient) DeriveNoise(_ []byte) ([]byte, error) {
	return nil, notImplemented
}

func (c *PKClient) GetPubKey() ([]byte, error) {
	return nil, notImplemented
}
