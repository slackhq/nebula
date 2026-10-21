package udp

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawSupported(t *testing.T) {
	assert.True(t, RawSupported(netip.MustParseAddrPort("1.2.3.4:4242")))
	assert.True(t, RawSupported(netip.MustParseAddrPort("[::ffff:1.2.3.4]:4242")))
	assert.False(t, RawSupported(netip.MustParseAddrPort("[2001:db8::1]:4242")))
	assert.False(t, RawSupported(netip.AddrPort{}))
}
