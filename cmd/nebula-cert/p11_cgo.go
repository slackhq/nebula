//go:build cgo && pkcs11

package main

import (
	"flag"
)

func p11Supported() bool {
	return true
}

func p11Flag(set *flag.FlagSet) *string {
	return set.String("pkcs11", "", "Optional: PKCS#11 URI to an existing private key")
}
