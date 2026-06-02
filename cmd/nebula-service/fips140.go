//go:build fips140v1.0 || fips140v1.26

package main

import (
	"crypto/fips140"
)

func init() {
	if !fips140.Enforced() {
		panic("Nebula compiled with fips140 expects FIPS140 to be enforced. Do not set GODEBUG=fips140, or if you do it must be set as GODEBUG=fips140=only")
	}
}
