package cert

import "errors"

var (
	ErrExpired       = errors.New("certificate is expired")
	ErrNotCA         = errors.New("certificate is not a CA")
	ErrNotSelfSigned = errors.New("certificate is not self-signed")
)
