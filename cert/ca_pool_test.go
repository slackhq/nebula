package cert

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewCAPoolFromBytes(t *testing.T) {
	noNewLines := `
# Current provisional, Remove once everything moves over to the real root.
-----BEGIN NEBULA CERTIFICATE-----
CkAKDm5lYnVsYSByb290IGNhKJfap9AFMJfg1+YGOiCUQGByMuNRhIlQBOyzXWbL
vcKBwDhov900phEfJ5DN3kABEkDCq5R8qBiu8sl54yVfgRcQXEDt3cHr8UTSLszv
bzBEr00kERQxxTzTsH8cpYEgRoipvmExvg8WP8NdAJEYJosB
-----END NEBULA CERTIFICATE-----
# root-ca01
-----BEGIN NEBULA CERTIFICATE-----
CkMKEW5lYnVsYSByb290IGNhIDAxKJL2u9EFMJL86+cGOiDPXMH4oU6HZTk/CqTG
BVG+oJpAoqokUBbI4U0N8CSfpUABEkB/Pm5A2xyH/nc8mg/wvGUWG3pZ7nHzaDMf
8/phAUt+FLzqTECzQKisYswKvE3pl9mbEYKbOdIHrxdIp95mo4sF
-----END NEBULA CERTIFICATE-----
`

	withNewLines := `
# Current provisional, Remove once everything moves over to the real root.

-----BEGIN NEBULA CERTIFICATE-----
CkAKDm5lYnVsYSByb290IGNhKJfap9AFMJfg1+YGOiCUQGByMuNRhIlQBOyzXWbL
vcKBwDhov900phEfJ5DN3kABEkDCq5R8qBiu8sl54yVfgRcQXEDt3cHr8UTSLszv
bzBEr00kERQxxTzTsH8cpYEgRoipvmExvg8WP8NdAJEYJosB
-----END NEBULA CERTIFICATE-----

# root-ca01


-----BEGIN NEBULA CERTIFICATE-----
CkMKEW5lYnVsYSByb290IGNhIDAxKJL2u9EFMJL86+cGOiDPXMH4oU6HZTk/CqTG
BVG+oJpAoqokUBbI4U0N8CSfpUABEkB/Pm5A2xyH/nc8mg/wvGUWG3pZ7nHzaDMf
8/phAUt+FLzqTECzQKisYswKvE3pl9mbEYKbOdIHrxdIp95mo4sF
-----END NEBULA CERTIFICATE-----

`

	expired := `
# expired certificate
-----BEGIN NEBULA CERTIFICATE-----
CjkKB2V4cGlyZWQouPmWjQYwufmWjQY6ILCRaoCkJlqHgv5jfDN4lzLHBvDzaQm4
vZxfu144hmgjQAESQG4qlnZi8DncvD/LDZnLgJHOaX1DWCHHEh59epVsC+BNgTie
WH1M9n4O7cFtGlM6sJJOS+rCVVEJ3ABS7+MPdQs=
-----END NEBULA CERTIFICATE-----
`

	p256 := `
# p256 certificate
-----BEGIN NEBULA CERTIFICATE-----
CmYKEG5lYnVsYSBQMjU2IHRlc3Qo4s+7mgYw4tXrsAc6QQRkaW2jFmllYvN4+/k2
6tctO9sPT3jOx8ES6M1nIqOhpTmZeabF/4rELDqPV4aH5jfJut798DUXql0FlF8H
76gvQAGgBgESRzBFAiEAib0/te6eMiZOKD8gdDeloMTS0wGuX2t0C7TFdUhAQzgC
IBNWYMep3ysx9zCgknfG5dKtwGTaqF++BWKDYdyl34KX
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
	assert.Nil(t, err)
	assert.Equal(t, p.CAs[string("c9bfaf7ce8e84b2eeda2e27b469f4b9617bde192efd214b68891ecda6ed49522")].Certificate.Name(), rootCA.details.name)
	assert.Equal(t, p.CAs[string("5c9c3f23e7ee7fe97637cbd3a0a5b854154d1d9aaaf7b566a51f4a88f76b64cd")].Certificate.Name(), rootCA01.details.name)

	pp, err := NewCAPoolFromPEM([]byte(withNewLines))
	assert.Nil(t, err)
	assert.Equal(t, pp.CAs[string("c9bfaf7ce8e84b2eeda2e27b469f4b9617bde192efd214b68891ecda6ed49522")].Certificate.Name(), rootCA.details.name)
	assert.Equal(t, pp.CAs[string("5c9c3f23e7ee7fe97637cbd3a0a5b854154d1d9aaaf7b566a51f4a88f76b64cd")].Certificate.Name(), rootCA01.details.name)

	// expired cert, no valid certs
	ppp, err := NewCAPoolFromPEM([]byte(expired))
	assert.Equal(t, ErrExpired, err)
	assert.Equal(t, ppp.CAs[string("152070be6bb19bc9e3bde4c2f0e7d8f4ff5448b4c9856b8eccb314fade0229b0")].Certificate.Name(), "expired")

	// expired cert, with valid certs
	pppp, err := NewCAPoolFromPEM(append([]byte(expired), noNewLines...))
	assert.Equal(t, ErrExpired, err)
	assert.Equal(t, pppp.CAs[string("c9bfaf7ce8e84b2eeda2e27b469f4b9617bde192efd214b68891ecda6ed49522")].Certificate.Name(), rootCA.details.name)
	assert.Equal(t, pppp.CAs[string("5c9c3f23e7ee7fe97637cbd3a0a5b854154d1d9aaaf7b566a51f4a88f76b64cd")].Certificate.Name(), rootCA01.details.name)
	assert.Equal(t, pppp.CAs[string("152070be6bb19bc9e3bde4c2f0e7d8f4ff5448b4c9856b8eccb314fade0229b0")].Certificate.Name(), "expired")
	assert.Equal(t, len(pppp.CAs), 3)

	ppppp, err := NewCAPoolFromPEM([]byte(p256))
	assert.Nil(t, err)
	assert.Equal(t, ppppp.CAs[string("a7938893ec8c4ef769b06d7f425e5e46f7a7f5ffa49c3bcf4a86b608caba9159")].Certificate.Name(), rootCAP256.details.name)
	assert.Equal(t, len(ppppp.CAs), 1)
}

func TestCertificateV1_Verify(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test cert", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	assert.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	assert.Nil(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	assert.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test cert2", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version1, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	assert.Nil(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test2", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)
}

func TestCertificateV1_VerifyP256(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	assert.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	assert.Nil(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	assert.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version1, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	assert.Nil(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)
}

func TestCertificateV1_Verify_IPs(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})

	caPem, err := ca.MarshalPEM()
	assert.Nil(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
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
	assert.Nil(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp2, caIp1}, nil, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1}, nil, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)
}

func TestCertificateV1_Verify_Subnets(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version1, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})

	caPem, err := ca.MarshalPEM()
	assert.Nil(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
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
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp2, caIp1}, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version1, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1}, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)
}

func TestCertificateV2_Verify(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test cert", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	assert.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	assert.Nil(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	assert.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test cert2", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	assert.Nil(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test2", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)
}

func TestCertificateV2_VerifyP256(t *testing.T) {
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, nil)
	c, _, _, _ := NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, nil)

	caPool := NewCAPool()
	assert.NoError(t, caPool.AddCA(ca))

	f, err := c.Fingerprint()
	assert.Nil(t, err)
	caPool.BlocklistFingerprint(f)

	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	_, err = caPool.VerifyCertificate(time.Now().Add(time.Hour*1000), c)
	assert.EqualError(t, err, "root certificate is expired")

	assert.PanicsWithError(t, "certificate is valid before the signing certificate", func() {
		NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Time{}, time.Time{}, nil, nil, nil)
	})

	// Test group assertion
	ca, _, caKey, _ = NewTestCaCert(Version2, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{"test1", "test2"})
	caPem, err := ca.MarshalPEM()
	assert.Nil(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)
}

func TestCertificateV2_Verify_IPs(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})

	caPem, err := ca.MarshalPEM()
	assert.Nil(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
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
	assert.Nil(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp2, caIp1}, nil, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{caIp1}, nil, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)
}

func TestCertificateV2_Verify_Subnets(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})

	caPem, err := ca.MarshalPEM()
	assert.Nil(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
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
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1, caIp2}, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches reversed
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp2, caIp1}, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)

	// Exact matches reversed with just 1
	c, _, _, _ = NewTestCert(Version2, Curve_CURVE25519, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, []netip.Prefix{caIp1}, []string{"test"})
	assert.Nil(t, err)
	_, err = caPool.VerifyCertificate(time.Now(), c)
	assert.Nil(t, err)
}
