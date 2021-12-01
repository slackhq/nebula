package cert

import "errors"

var (
	ErrEmptyCAPool   = errors.New("ca pool had no valid certificates")
	ErrExpired       = errors.New("certificate is expired")
	ErrNotCA         = errors.New("certificate is not a CA")
	ErrNotSelfSigned = errors.New("certificate is not self-signed")
)
