//go:build boringcrypto

package nebula

import "crypto/boring"

func getFIPS140() string {
	if boring.Enabled() {
		return "boringcrypto"
	}
	return "off"
}
