package cert

import (
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// readOptionalASN1Boolean reads an asn.1 boolean with a specific tag instead of a asn.1 tag wrapping a boolean with a value
// https://github.com/golang/go/issues/64811#issuecomment-1944446920
func readOptionalASN1Boolean(b *cryptobyte.String, out *bool, tag asn1.Tag, defaultValue bool) bool {
	var present bool
	var child cryptobyte.String
	if !b.ReadOptionalASN1(&child, &present, tag) {
		return false
	}

	if !present {
		*out = defaultValue
		return true
	}

	// Ensure we have 1 byte
	if len(child) == 1 {
		*out = child[0] > 0
		return true
	}

	return false
}

// readOptionalASN1Byte reads an asn.1 uint8 with a specific tag instead of a asn.1 tag wrapping a uint8 with a value
// Similar issue as with readOptionalASN1Boolean
func readOptionalASN1Byte(b *cryptobyte.String, out *byte, tag asn1.Tag, defaultValue byte) bool {
	var present bool
	var child cryptobyte.String
	if !b.ReadOptionalASN1(&child, &present, tag) {
		return false
	}

	if !present {
		*out = defaultValue
		return true
	}

	// Ensure we have 1 byte
	if len(child) == 1 {
		*out = child[0]
		return true
	}

	return false
}
