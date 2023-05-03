package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

var ErrNoTerminal = errors.New("cannot read password from nonexistent terminal")

type PasswordReader interface {
	ReadPassword() ([]byte, error)
}

type StdinPasswordReader struct{}

func (pr StdinPasswordReader) ReadPassword() ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, ErrNoTerminal
	}

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	return password, err
}
