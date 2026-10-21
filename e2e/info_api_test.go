//go:build e2e_testing

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/localapi"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIdentityOverTheInfoAPI is the info API's reason to exist, end to end: a program on
// this host has a connection arriving over the overlay and asks who is behind its
// source address, and the answer is the identity in the certificate the tunnel was
// established with.
func TestIdentityOverTheInfoAPI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test's HTTP helpers dial unix sockets; on windows the info API is a named pipe")
	}

	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version2, ca, caKey, "me", "10.128.0.1/24", nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version2, ca, caKey, "them", "10.128.0.2/24", nil)

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	theirControl.Start()
	t.Cleanup(func() {
		myControl.Stop()
		theirControl.Stop()
	})

	// Before the tunnel is up their address is unknown to us.
	path := infoSocket(t)
	info := localapi.NewInfoServer(NewTestLogger(), myControl.InfoHandler())
	require.NoError(t, info.Rebind(context.Background(), path, localapi.Access{Mode: 0600}))
	t.Cleanup(info.Stop)

	status, body := test.HTTPGet(t, path, "/v1/identity/"+theirVpnIpNet[0].Addr().String())
	assert.Equal(t, http.StatusNotFound, status)
	assert.JSONEq(t, `{"error":"No active tunnel for vpn addr: 10.128.0.2"}`, body)

	// Only we know how to reach them, so the first packet has to be ours; once the tunnel
	// is up both directions work and assertTunnel can check it.
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from me")))
	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)
	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	type identity struct {
		Name        string         `json:"name"`
		VpnAddrs    []netip.Addr   `json:"vpnAddrs"`
		Networks    []netip.Prefix `json:"networks"`
		Groups      []string       `json:"groups"`
		Issuer      string         `json:"issuer"`
		Fingerprint string         `json:"fingerprint"`
	}

	// A connection's RemoteAddr, port and all, is the resource's path and resolves to the
	// peer.
	theirAddrPort := netip.AddrPortFrom(theirVpnIpNet[0].Addr(), 51234).String()
	status, body = test.HTTPGet(t, path, "/v1/identity/"+theirAddrPort)
	require.Equal(t, http.StatusOK, status, body)
	var them identity
	require.NoError(t, json.Unmarshal([]byte(body), &them))
	assert.Equal(t, "them", them.Name)
	assert.Equal(t, []netip.Addr{theirVpnIpNet[0].Addr()}, them.VpnAddrs)
	assert.Equal(t, theirVpnIpNet, them.Networks)
	assert.Equal(t, []string{}, them.Groups)
	caFP, err := ca.Fingerprint()
	require.NoError(t, err)
	assert.Equal(t, caFP, them.Issuer)
	assert.NotContains(t, body, `"pem"`, "the certificate is its own resource")

	// The certificate itself is the identity's pem sub-resource, for a program that
	// verifies it against its own CAs: the one nebula verified when the tunnel came up.
	status, body = test.HTTPGet(t, path, "/v1/identity/"+theirAddrPort+"/pem")
	require.Equal(t, http.StatusOK, status, body)
	var raw struct {
		PEM string `json:"pem"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &raw))
	theirs, _, err := cert.UnmarshalCertificateFromPEM([]byte(raw.PEM))
	require.NoError(t, err)
	assert.Equal(t, "them", theirs.Name())
	fp, err := theirs.Fingerprint()
	require.NoError(t, err)
	assert.Equal(t, them.Fingerprint, fp, "the same certificate the identity was read from")

	// The resource itself is this node, and so is its pem.
	status, body = test.HTTPGet(t, path, "/v1/identity")
	require.Equal(t, http.StatusOK, status, body)
	var me identity
	require.NoError(t, json.Unmarshal([]byte(body), &me))
	assert.Equal(t, "me", me.Name)
	assert.Equal(t, []netip.Addr{myVpnIpNet[0].Addr()}, me.VpnAddrs)

	status, body = test.HTTPGet(t, path, "/v1/identity/pem")
	require.Equal(t, http.StatusOK, status, body)
	require.NoError(t, json.Unmarshal([]byte(body), &raw))
	mine, _, err := cert.UnmarshalCertificateFromPEM([]byte(raw.PEM))
	require.NoError(t, err)
	assert.Equal(t, "me", mine.Name())

	// An empty address is a caller's bug: a program that built the path from an address
	// it failed to fill in gets no route, never this node's identity to authorize against.
	status, body = test.HTTPGet(t, path, "/v1/identity/")
	assert.Equal(t, http.StatusNotFound, status)
	assert.Contains(t, body, "no such path")

	status, body = test.HTTPGet(t, path, "/v1/identity/not-an-address")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.JSONEq(t, `{"error":"The provided vpn addr could not be parsed: not-an-address"}`, body)

	// Nothing else nebula serves is reachable here: a command's name is just a path
	// that is not served.
	status, body = test.HTTPGet(t, path, "/v1/list-hostmap")
	assert.Equal(t, http.StatusNotFound, status)
	assert.Contains(t, body, "no such path")
	status, _ = test.HTTPGet(t, path, "/v1/print-tunnel/"+theirAddrPort)
	assert.Equal(t, http.StatusNotFound, status)

	r.RenderHostmaps("Final hostmaps", myControl, theirControl)
}

// infoSocket returns a short socket path in a private directory, one level below it
// so that listen has a directory of its own to create.
func infoSocket(t *testing.T) string {
	t.Helper()
	return filepath.Join(test.ShortTempDir(t), "n", "info.sock")
}
