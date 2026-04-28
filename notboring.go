//go:build !boringcrypto

package nebula

import (
	"crypto/fips140"
	"runtime/debug"
)

func getFIPS140() string {
	switch {
	case fips140.Enabled():
		return getFIPS140Version()
	default:
		return "off"
	}
}

func getFIPS140Version() string {
	// The docs for fips140.Version mention this is more accurate to
	// get the exact version
	// - https://pkg.go.dev/crypto/fips140#Version
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range info.Settings {
			if s.Key == "GOFIPS140" {
				return s.Value
			}
		}
	}
	// TODO: Add as a backup once we bump to go1.26+
	// return fips140.Version()
	return ""
}
