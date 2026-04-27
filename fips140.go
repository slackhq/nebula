package nebula

import (
	"crypto/fips140"
	"runtime/debug"
)

func getFIPS140() string {
	switch {
	case fips140.Enforced():
		return "only"
	case fips140.Enabled():
		return "on"
	default:
		return "off"
	}
}

func getFIPS140Version() string {
	// The docs for fips140.Version mention this is more accurate to
	// get the exact version
	info, ok := debug.ReadBuildInfo()
	if ok {
		for _, s := range info.Settings {
			if s.Key == "GOFIPS140" {
				return s.Value
			}
		}
	}
	return fips140.Version()
}
