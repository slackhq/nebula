//go:build boringcrypto
// +build boringcrypto

package nebula

import "crypto/boring"

var boringEnabled = boring.Enabled
