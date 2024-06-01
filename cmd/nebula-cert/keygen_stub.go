//go:build !cgo || !pkcs11

package main

func keygenP11flag(cf *keygenFlags) {
	var e = ""
	cf.p11url = &e
}
