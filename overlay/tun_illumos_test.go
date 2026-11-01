//go:build illumos && !e2e_testing

package overlay

import (
	"net/netip"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func decodeRouteHdr(t *testing.T, msg []byte) unix.RtMsghdr {
	t.Helper()
	require.GreaterOrEqual(t, len(msg), unix.SizeofRtMsghdr)
	var hdr unix.RtMsghdr
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), unix.SizeofRtMsghdr), msg)
	return hdr
}

func decodeSockaddr4(t *testing.T, b []byte) netip.Addr {
	t.Helper()
	require.GreaterOrEqual(t, len(b), unix.SizeofSockaddrInet4)
	var sa unix.RawSockaddrInet4
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), unix.SizeofSockaddrInet4), b)
	require.Equal(t, uint16(unix.AF_INET), sa.Family)
	return netip.AddrFrom4(sa.Addr)
}

func decodeSockaddr6(t *testing.T, b []byte) netip.Addr {
	t.Helper()
	require.GreaterOrEqual(t, len(b), unix.SizeofSockaddrInet6)
	var sa unix.RawSockaddrInet6
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&sa)), unix.SizeofSockaddrInet6), b)
	require.Equal(t, uint16(unix.AF_INET6), sa.Family)
	return netip.AddrFrom16(sa.Addr)
}

func TestBuildRouteMsg_IPv4Network(t *testing.T) {
	// An unmasked prefix is masked, and the gateway is the local vpn address
	msg := buildRouteMsg(unix.RTM_ADD, 7, netip.MustParsePrefix("192.168.100.1/24"), netip.MustParseAddr("192.168.100.1"), 0)

	require.Len(t, msg, unix.SizeofRtMsghdr+3*unix.SizeofSockaddrInet4)
	hdr := decodeRouteHdr(t, msg)
	assert.Equal(t, uint16(len(msg)), hdr.Msglen)
	assert.Equal(t, uint8(unix.RTM_VERSION), hdr.Version)
	assert.Equal(t, uint8(unix.RTM_ADD), hdr.Type)
	assert.Equal(t, int32(7), hdr.Seq)
	assert.Equal(t, int32(unix.RTF_UP|unix.RTF_STATIC), hdr.Flags, "an interface route has RTF_GATEWAY clear")
	assert.Equal(t, int32(unix.RTA_DST|unix.RTA_GATEWAY|unix.RTA_NETMASK), hdr.Addrs)
	assert.Zero(t, hdr.Inits, "no mtu was asked for")

	off := unix.SizeofRtMsghdr
	assert.Equal(t, netip.MustParseAddr("192.168.100.0"), decodeSockaddr4(t, msg[off:]))
	off += unix.SizeofSockaddrInet4
	assert.Equal(t, netip.MustParseAddr("192.168.100.1"), decodeSockaddr4(t, msg[off:]))
	off += unix.SizeofSockaddrInet4
	assert.Equal(t, netip.MustParseAddr("255.255.255.0"), decodeSockaddr4(t, msg[off:]))
}

func TestBuildRouteMsg_IPv4Host(t *testing.T) {
	msg := buildRouteMsg(unix.RTM_DELETE, 1, netip.MustParsePrefix("10.1.2.3/32"), netip.MustParseAddr("192.168.100.1"), 0)

	require.Len(t, msg, unix.SizeofRtMsghdr+2*unix.SizeofSockaddrInet4, "a host route carries no netmask")
	hdr := decodeRouteHdr(t, msg)
	assert.Equal(t, uint8(unix.RTM_DELETE), hdr.Type)
	assert.Equal(t, int32(unix.RTF_UP|unix.RTF_STATIC|unix.RTF_HOST), hdr.Flags)
	assert.Equal(t, int32(unix.RTA_DST|unix.RTA_GATEWAY), hdr.Addrs)
	assert.Equal(t, netip.MustParseAddr("10.1.2.3"), decodeSockaddr4(t, msg[unix.SizeofRtMsghdr:]))
}

func TestBuildRouteMsg_IPv6WithMTU(t *testing.T) {
	msg := buildRouteMsg(unix.RTM_CHANGE, 2, netip.MustParsePrefix("fd00:200::1/64"), netip.MustParseAddr("fd00:200::1"), 1280)

	require.Len(t, msg, unix.SizeofRtMsghdr+3*unix.SizeofSockaddrInet6)
	hdr := decodeRouteHdr(t, msg)
	assert.Equal(t, uint16(len(msg)), hdr.Msglen)
	assert.Equal(t, uint8(unix.RTM_CHANGE), hdr.Type)
	assert.Equal(t, int32(unix.RTA_DST|unix.RTA_GATEWAY|unix.RTA_NETMASK), hdr.Addrs)
	assert.Equal(t, uint32(unix.RTV_MTU), hdr.Inits)
	assert.Equal(t, uint32(1280), hdr.Rmx.Mtu)

	off := unix.SizeofRtMsghdr
	assert.Equal(t, netip.MustParseAddr("fd00:200::"), decodeSockaddr6(t, msg[off:]))
	off += unix.SizeofSockaddrInet6
	assert.Equal(t, netip.MustParseAddr("fd00:200::1"), decodeSockaddr6(t, msg[off:]))
	off += unix.SizeofSockaddrInet6
	assert.Equal(t, netip.MustParseAddr("ffff:ffff:ffff:ffff::"), decodeSockaddr6(t, msg[off:]))
}

func TestRouteMTU(t *testing.T) {
	tn := &tun{MTU: 1300}
	assert.Equal(t, 1300, tn.routeMTU(Route{}), "a route without an mtu takes tun.mtu")
	assert.Equal(t, 8800, tn.routeMTU(Route{MTU: 8800}))
}
