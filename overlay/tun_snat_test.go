package overlay

import (
	"io"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDevice is a minimal Device implementation for testing prepareUnsafeOriginAddr.
type mockDevice struct {
	networks       []netip.Prefix
	unsafeNetworks []netip.Prefix
	snatAddr       netip.Prefix
	unsafeSnatAddr netip.Prefix
}

func (d *mockDevice) Read([]byte) (int, error)                         { return 0, nil }
func (d *mockDevice) Write([]byte) (int, error)                        { return 0, nil }
func (d *mockDevice) Close() error                                     { return nil }
func (d *mockDevice) Activate() error                                  { return nil }
func (d *mockDevice) Networks() []netip.Prefix                         { return d.networks }
func (d *mockDevice) UnsafeNetworks() []netip.Prefix                   { return d.unsafeNetworks }
func (d *mockDevice) SNATAddress() netip.Prefix                        { return d.snatAddr }
func (d *mockDevice) UnsafeIPv4OriginAddress() netip.Prefix            { return d.unsafeSnatAddr }
func (d *mockDevice) Name() string                                     { return "mock" }
func (d *mockDevice) RoutesFor(netip.Addr) routing.Gateways            { return routing.Gateways{} }
func (d *mockDevice) SupportsMultiqueue() bool                         { return false }
func (d *mockDevice) NewMultiQueueReader() (io.ReadWriteCloser, error) { return nil, nil }

func TestPrepareSnatAddr_V4Primary_NoSnat(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	c := config.NewC(l)

	// If the device has an IPv4 primary address, no SNAT needed
	d := &mockDevice{
		networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	}
	result := prepareUnsafeOriginAddr(d, l, c, nil)
	assert.Equal(t, netip.Prefix{}, result, "should not assign SNAT addr when device has IPv4 primary")
}

func TestPrepareSnatAddr_V6Primary_NoUnsafeOrRoutes(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	c := config.NewC(l)

	// IPv6 primary but no unsafe networks or IPv4 routes
	d := &mockDevice{
		networks: []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
	}
	result := prepareUnsafeOriginAddr(d, l, c, nil)
	assert.Equal(t, netip.Prefix{}, result, "should not assign SNAT addr without IPv4 unsafe networks or routes")
}

func TestPrepareSnatAddr_V6Primary_WithV4Unsafe(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	c := config.NewC(l)

	// IPv6 primary with IPv4 unsafe network -> should get SNAT addr
	d := &mockDevice{
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	}
	result := prepareSnatAddr(d, l, c)
	require.True(t, result.IsValid(), "should assign SNAT addr")
	assert.True(t, result.Addr().Is4(), "SNAT addr should be IPv4")
	assert.True(t, result.Addr().IsLinkLocalUnicast(), "SNAT addr should be link-local")
	assert.Equal(t, 32, result.Bits(), "SNAT addr should be /32")

	result = prepareUnsafeOriginAddr(d, l, c, nil)
	require.False(t, result.IsValid(), "no routes = no origin addr needed")
}

func TestPrepareUnsafeOriginAddr_V6Primary_WithV4Route(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	c := config.NewC(l)

	// IPv6 primary with IPv4 route -> should get SNAT addr
	d := &mockDevice{
		networks: []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
	}
	routes := []Route{
		{Cidr: netip.MustParsePrefix("10.0.0.0/8")},
	}
	result := prepareUnsafeOriginAddr(d, l, c, routes)
	require.True(t, result.IsValid(), "should assign SNAT addr when IPv4 route exists")
	assert.True(t, result.Addr().Is4())
	assert.True(t, result.Addr().IsLinkLocalUnicast())

	result = prepareSnatAddr(d, l, c)
	require.False(t, result.IsValid(), "no UnsafeNetworks = no snat addr needed")
}

func TestPrepareSnatAddr_V6Primary_V6UnsafeOnly(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	c := config.NewC(l)

	// IPv6 primary with only IPv6 unsafe network -> no SNAT needed
	d := &mockDevice{
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("fd01::/64")},
	}
	result := prepareUnsafeOriginAddr(d, l, c, nil)
	assert.Equal(t, netip.Prefix{}, result, "should not assign SNAT addr for IPv6-only unsafe networks")
}

func TestPrepareSnatAddr_ManualAddress(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	c := config.NewC(l)
	c.Settings["tun"] = map[string]any{
		"snat_address_for_4over6": "169.254.42.42",
	}

	d := &mockDevice{
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	}
	result := prepareSnatAddr(d, l, c)
	require.True(t, result.IsValid())
	assert.Equal(t, netip.MustParseAddr("169.254.42.42"), result.Addr())
	assert.Equal(t, 32, result.Bits())
}

func TestPrepareSnatAddr_InvalidManualAddress_Fallback(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	c := config.NewC(l)
	c.Settings["tun"] = map[string]any{
		"snat_address_for_4over6": "not-an-ip",
	}

	d := &mockDevice{
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	}
	result := prepareSnatAddr(d, l, c)
	// Should fall back to auto-assignment
	require.True(t, result.IsValid(), "should fall back to auto-assigned address")
	assert.True(t, result.Addr().Is4())
	assert.True(t, result.Addr().IsLinkLocalUnicast())
}

func TestPrepareSnatAddr_AutoGenerated_Range(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	c := config.NewC(l)

	d := &mockDevice{
		networks:       []netip.Prefix{netip.MustParsePrefix("fd00::1/128")},
		unsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	}

	// Generate several addresses and verify they're all in the expected range
	for i := 0; i < 100; i++ {
		result := prepareSnatAddr(d, l, c)
		require.True(t, result.IsValid())
		addr := result.Addr()
		octets := addr.As4()
		assert.Equal(t, byte(169), octets[0], "first octet should be 169")
		assert.Equal(t, byte(254), octets[1], "second octet should be 254")
		// Should not have .0 in the last octet
		assert.NotEqual(t, byte(0), octets[3], "last octet should not be 0")
		// Should not be 169.254.255.255 (broadcast)
		if octets[2] == 255 {
			assert.NotEqual(t, byte(255), octets[3], "should not be broadcast address")
		}
	}
}
