package nebula

import (
	"github.com/stretchr/testify/assert"
	"net/netip"
	"testing"
)

func TestInfo_shouldAllowBinding(t *testing.T) {

	tests := []struct {
		name       string
		addr       netip.Addr
		shouldPass bool
	}{
		{
			name:       "Allow binding to local IPv4",
			addr:       netip.MustParseAddr("127.0.0.1"),
			shouldPass: true,
		},
		{
			name:       "Allow binding to local IPv6",
			addr:       netip.MustParseAddr("::1"),
			shouldPass: true,
		},
		{
			name:       "Error binding to private IPv4",
			addr:       netip.MustParseAddr("192.168.1.1"),
			shouldPass: false,
		},
		{
			name:       "Error binding to private IPv6",
			addr:       netip.MustParseAddr("fd00::1"),
			shouldPass: false,
		},
		{
			name:       "Error binding to public IPv4",
			addr:       netip.MustParseAddr("1.1.1.1"),
			shouldPass: false,
		},
		{ // Some random unallocated IPv6 address
			name:       "Error binding to public IPv6",
			addr:       netip.MustParseAddr("0cbb:c1ed:6a53:ca6b:f69f:8842:1ace:9ec0"),
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := shouldAllowBinding(tt.addr)

			if tt.shouldPass {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
