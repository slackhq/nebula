//go:build !cgo || !pkcs11

package main

func keygenP11flag(cf *keygenFlags) {
	// do nothing
}
