package overlay

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinkLocal(t *testing.T) {
	r := bytes.NewReader([]byte{42, 99})
	result := genLinkLocal(r)
	assert.Equal(t, netip.MustParsePrefix("169.254.42.99/32"), result, "genLinkLocal with a deterministic randomizer")

	result = genLinkLocal(nil)
	assert.True(t, result.IsValid(), "genLinkLocal with nil randomizer should be valid")
	assert.True(t, result.Addr().IsLinkLocalUnicast(), "genLinkLocal with nil randomizer should be link-local")

	result = coerceLinkLocal([]byte{169, 254, 100, 50})
	assert.Equal(t, netip.MustParsePrefix("169.254.100.50/32"), result, "coerceLinkLocal should pass through normal values")

	result = coerceLinkLocal([]byte{169, 254, 0, 0})
	assert.Equal(t, netip.MustParsePrefix("169.254.0.1/32"), result, "coerceLinkLocal should bump .0 last octet to .1")

	result = coerceLinkLocal([]byte{169, 254, 255, 255})
	assert.Equal(t, netip.MustParsePrefix("169.254.255.254/32"), result, "coerceLinkLocal should bump broadcast 255.255 to 255.254")

	result = coerceLinkLocal([]byte{169, 254, 0, 1})
	assert.Equal(t, netip.MustParsePrefix("169.254.0.1/32"), result, "coerceLinkLocal should leave .1 last octet unchanged")

	result = coerceLinkLocal([]byte{169, 254, 255, 254})
	assert.Equal(t, netip.MustParsePrefix("169.254.255.254/32"), result, "coerceLinkLocal should leave 255.254 unchanged")

	result = coerceLinkLocal([]byte{169, 254, 255, 100})
	assert.Equal(t, netip.MustParsePrefix("169.254.255.100/32"), result, "coerceLinkLocal should leave 255.100 unchanged")
}
