package cert

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCAPoolFromBytes(t *testing.T) {
	noNewLines := `
# Current provisional, Remove once everything moves over to the real root.
-----BEGIN NEBULA CERTIFICATE-----
Cj4KDm5lYnVsYSByb290IGNhKM0cMM24zPCvBzogV24YEw5YiqeI/oYo8XXFsoo+
PBmiOafNJhLacf9rsspAARJAz9OAnh8TKAUKix1kKVMyQU4iM3LsFfZRf6ODWXIf
2qWMpB6fpd3PSoVYziPoOt2bIHIFLlgRLPJz3I3xBEdBCQ==
-----END NEBULA CERTIFICATE-----
# root-ca01
-----BEGIN NEBULA CERTIFICATE-----
CkEKEW5lYnVsYSByb290IGNhIDAxKM0cMM24zPCvBzogPzbWTxt8ZgXPQEwup7Br
BrtIt1O0q5AuTRT3+t2x1VJAARJAZ+2ib23qBXjdy49oU1YysrwuKkWWKrtJ7Jye
rFBQpDXikOukhQD/mfkloFwJ+Yjsfru7IpTN4ZfjXL+kN/2sCA==
-----END NEBULA CERTIFICATE-----
`

	withNewLines := `
# Current provisional, Remove once everything moves over to the real root.

-----BEGIN NEBULA CERTIFICATE-----
Cj4KDm5lYnVsYSByb290IGNhKM0cMM24zPCvBzogV24YEw5YiqeI/oYo8XXFsoo+
PBmiOafNJhLacf9rsspAARJAz9OAnh8TKAUKix1kKVMyQU4iM3LsFfZRf6ODWXIf
2qWMpB6fpd3PSoVYziPoOt2bIHIFLlgRLPJz3I3xBEdBCQ==
-----END NEBULA CERTIFICATE-----

# root-ca01


-----BEGIN NEBULA CERTIFICATE-----
CkEKEW5lYnVsYSByb290IGNhIDAxKM0cMM24zPCvBzogPzbWTxt8ZgXPQEwup7Br
BrtIt1O0q5AuTRT3+t2x1VJAARJAZ+2ib23qBXjdy49oU1YysrwuKkWWKrtJ7Jye
rFBQpDXikOukhQD/mfkloFwJ+Yjsfru7IpTN4ZfjXL+kN/2sCA==
-----END NEBULA CERTIFICATE-----

`

	expired := `
# expired certificate
-----BEGIN NEBULA CERTIFICATE-----
CjMKB2V4cGlyZWQozRwwzRw6ICJSG94CqX8wn5I65Pwn25V6HftVfWeIySVtp2DA
7TY/QAESQMaAk5iJT5EnQwK524ZaaHGEJLUqqbh5yyOHhboIGiVTWkFeH3HccTW8
Tq5a8AyWDQdfXbtEZ1FwabeHfH5Asw0=
-----END NEBULA CERTIFICATE-----
`

	p256 := `
# p256 certificate
-----BEGIN NEBULA CERTIFICATE-----
CmQKEG5lYnVsYSBQMjU2IHRlc3QozRwwzbjM8K8HOkEEdrmmg40zQp44AkMq6DZp
k+coOv04r+zh33ISyhbsafnYduN17p2eD7CmHvHuerguXD9f32gcxo/KsFCKEjMe
+0ABoAYBEkcwRQIgVoTg38L7uWku9xQgsr06kxZ/viQLOO/w1Qj1vFUEnhcCIQCq
75SjTiV92kv/1GcbT3wWpAZQQDBiUHVMVmh1822szA==
-----END NEBULA CERTIFICATE-----
`

	rootCA := certificateV1{
		details: detailsV1{
			name: "nebula root ca",
		},
	}

	rootCA01 := certificateV1{
		details: detailsV1{
			name: "nebula root ca 01",
		},
	}

	rootCAP256 := certificateV1{
		details: detailsV1{
			name: "nebula P256 test",
		},
	}

	p, err := NewCAPoolFromPEM([]byte(noNewLines))
	require.NoError(t, err)
	assert.Equal(t, p.CAs["ce4e6c7a596996eb0d82a8875f0f0137a4b53ce22d2421c9fd7150e7a26f6300"].Certificate.Name(), rootCA.details.name)
	assert.Equal(t, p.CAs["04c585fcd9a49b276df956a22b7ebea3bf23f1fca5a17c0b56ce2e626631969e"].Certificate.Name(), rootCA01.details.name)

	pp, err := NewCAPoolFromPEM([]byte(withNewLines))
	require.NoError(t, err)
	assert.Equal(t, pp.CAs["ce4e6c7a596996eb0d82a8875f0f0137a4b53ce22d2421c9fd7150e7a26f6300"].Certificate.Name(), rootCA.details.name)
	assert.Equal(t, pp.CAs["04c585fcd9a49b276df956a22b7ebea3bf23f1fca5a17c0b56ce2e626631969e"].Certificate.Name(), rootCA01.details.name)

	// expired cert, no valid certs
	ppp, err := NewCAPoolFromPEM([]byte(expired))
	assert.Equal(t, ErrExpired, err)
	assert.Equal(t, "expired", ppp.CAs["c39b35a0e8f246203fe4f32b9aa8bfd155f1ae6a6be9d78370641e43397f48f5"].Certificate.Name())

	// expired cert, with valid certs
	pppp, err := NewCAPoolFromPEM(append([]byte(expired), noNewLines...))
	assert.Equal(t, ErrExpired, err)
	assert.Equal(t, pppp.CAs["ce4e6c7a596996eb0d82a8875f0f0137a4b53ce22d2421c9fd7150e7a26f6300"].Certificate.Name(), rootCA.details.name)
	assert.Equal(t, pppp.CAs["04c585fcd9a49b276df956a22b7ebea3bf23f1fca5a17c0b56ce2e626631969e"].Certificate.Name(), rootCA01.details.name)
	assert.Equal(t, "expired", pppp.CAs["c39b35a0e8f246203fe4f32b9aa8bfd155f1ae6a6be9d78370641e43397f48f5"].Certificate.Name())
	assert.Len(t, pppp.CAs, 3)

	ppppp, err := NewCAPoolFromPEM([]byte(p256))
	require.NoError(t, err)
	assert.Equal(t, ppppp.CAs["552bf7d99bec1fc775a0e4c324bf6d8f789b3078f1919c7960d2e5e0c351ee97"].Certificate.Name(), rootCAP256.details.name)
	assert.Len(t, ppppp.CAs, 1)
}

func TestCertificateV1_Verify(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test cert", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	require.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	require.NoError(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	require.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test cert2", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version1, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test2", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV1_VerifyP256(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	require.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	require.NoError(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	require.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version1, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV1_Verify_IPs(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.1.0.0/24")
	cIp2 := mustParsePrefixUnmapped("192.168.0.1/16")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is outside the network reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.1.0.0/24")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is within the network but mask is outside
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/15")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/24")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is within the network but mask is outside reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.0.1.0/15")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip and mask are within the network
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/16")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/25")
	c, _, _, _ := NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp2, caIp1}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV1_Verify_Subnets(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.1.0.0/24")
	cIp2 := mustParsePrefixUnmapped("192.168.0.1/16")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is outside the network reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.1.0.0/24")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is within the network but mask is outside
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/15")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/24")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is within the network but mask is outside reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.0.1.0/15")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip and mask are within the network
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/16")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/25")
	c, _, _, _ := NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp2, caIp1}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV2_Verify(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test cert", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	require.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	require.NoError(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	require.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test cert2", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test2", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV2_VerifyP256(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	require.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	require.NoError(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	require.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version2, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV2_Verify_IPs(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.1.0.0/24")
	cIp2 := mustParsePrefixUnmapped("192.168.0.1/16")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is outside the network reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.1.0.0/24")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is within the network but mask is outside
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/15")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/24")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip is within the network but mask is outside reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.0.1.0/15")
	assert.PanicsWithError(t, "certificate contained a network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	})

	// ip and mask are within the network
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/16")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/25")
	c, _, _, _ := NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1, cIp2}, nil, []string{"test"})
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp2, caIp1}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1}, nil, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}

func TestCertificateV2_Verify_Subnets(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.1.0.0/24")
	cIp2 := mustParsePrefixUnmapped("192.168.0.1/16")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is outside the network reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.1.0.0/24")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.1.0.0/24", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is within the network but mask is outside
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/15")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/24")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip is within the network but mask is outside reversed order of above
	cIp1 = mustParsePrefixUnmapped("192.168.0.1/24")
	cIp2 = mustParsePrefixUnmapped("10.0.1.0/15")
	assert.PanicsWithError(t, "certificate contained an unsafe network assignment outside the limitations of the signing ca: 10.0.1.0/15", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	})

	// ip and mask are within the network
	cIp1 = mustParsePrefixUnmapped("10.0.1.0/16")
	cIp2 = mustParsePrefixUnmapped("192.168.0.1/25")
	c, _, _, _ := NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{cIp1, cIp2}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp2, caIp1}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1}, []string{"test"})
	require.NoError(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)
}
