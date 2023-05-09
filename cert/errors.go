package cert

import (
	"errors"
)

var (
	ErrRootExpired       = errors.New("root certificate is expired")
	ErrExpired           = errors.New("certificate is expired")
	ErrNotCA             = errors.New("certificate is not a CA")
	ErrNotSelfSigned     = errors.New("certificate is not self-signed")
	ErrBlockListed       = errors.New("certificate is in the block list")
	ErrSignatureMismatch = errors.New("certificate signature did not match")
)
