package nebula

import (
	"crypto/fips140"
	"fmt"
)

func fips140version() string {
	switch {
	case fips140.Enforced():
		return fmt.Sprintf("only,version=%s", fips140.Version())
	case fips140.Enabled():
		return fmt.Sprintf("on,version=%s", fips140.Version())
	default:
		return "off"
	}
}
