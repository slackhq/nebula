//go:build !cgo || !pkcs11

package main

import (
	"flag"
)

func p11Supported() bool {
	return false
}

func p11Flag(set *flag.FlagSet) *string {
	var ret = ""
	return &ret
}
