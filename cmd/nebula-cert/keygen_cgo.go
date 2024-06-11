//go:build cgo && pkcs11

package main

func keygenP11flag(cf *keygenFlags) {
	cf.p11url = cf.set.String("pkcs11", "", "Optional PKCS11 URL to an existing private key to obtain a nebula public key from")
}
