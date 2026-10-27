package cert

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert/p256"
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

// A bundle can hold CAs a newer nebula understands, those are skipped and reported along with the pool. Anything else
// that fails to load still fails the whole pool.
func TestNewCAPoolFromPEM_SkipsUnsupported(t *testing.T) {
	ca, _, _, caPEM := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	fp, err := ca.Fingerprint()
	require.NoError(t, err)

	newCurve, _, _, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	nc := newCurve.Copy().(*certificateV2)
	nc.curve = Curve(2)
	newCurvePEM, err := nc.MarshalPEM()
	require.NoError(t, err)
	newVersionPEM := pem.EncodeToMemory(&pem.Block{Type: "NEBULA CERTIFICATE V9", Bytes: []byte{0x30, 0x00}})

	pool, err := NewCAPoolFromPEM(appendByteSlices(newVersionPEM, caPEM, newCurvePEM))
	require.NotNil(t, pool)
	require.ErrorIs(t, err, ErrUnknownVersion)
	require.ErrorIs(t, err, ErrUnknownCurve)
	require.NotErrorIs(t, err, ErrExpired)
	assert.Len(t, pool.CAs, 1)
	assert.Contains(t, pool.CAs, fp)

	// Expired CAs are still reported too
	_, _, _, expiredPEM := NewTestCaCert(Version2, Curve_CURVE25519, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil, nil, nil)
	pool, err = NewCAPoolFromPEM(appendByteSlices(caPEM, expiredPEM, newVersionPEM))
	require.NotNil(t, pool)
	require.ErrorIs(t, err, ErrExpired)
	require.ErrorIs(t, err, ErrUnknownVersion)
	assert.Len(t, pool.CAs, 2)

	// Nothing we can use is still a pool, the caller decides if an empty one is ok
	pool, err = NewCAPoolFromPEM(newVersionPEM)
	require.NotNil(t, pool)
	require.ErrorIs(t, err, ErrUnknownVersion)
	assert.Empty(t, pool.CAs)

	// A banner that isn't a nebula certificate at all is a mistake, not something newer
	notNebula := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}})
	pool, err = NewCAPoolFromPEM(appendByteSlices(caPEM, notNebula))
	assert.Nil(t, pool)
	require.ErrorIs(t, err, ErrInvalidPEMCertificateBanner)

	// A newer curve is only skipped once the rest of the certificate parses, a damaged one still fails the pool
	raw, err := nc.Marshal()
	require.NoError(t, err)
	sigTag := len(raw) - len(nc.signature) - 2
	require.Equal(t, byte(TagCertSignature), raw[sigTag])
	raw[sigTag] = 0x84
	damaged := pem.EncodeToMemory(&pem.Block{Type: CertificateV2Banner, Bytes: raw})
	pool, err = NewCAPoolFromPEM(appendByteSlices(caPEM, damaged))
	assert.Nil(t, pool)
	require.ErrorIs(t, err, ErrBadFormat)

	// So is a CA we understand that doesn't verify
	bad := ca.Copy().(*certificateV2)
	bad.signature = bytes.Repeat([]byte{1}, len(bad.signature))
	badPEM, err := bad.MarshalPEM()
	require.NoError(t, err)
	pool, err = NewCAPoolFromPEM(appendByteSlices(newVersionPEM, badPEM))
	assert.Nil(t, pool)
	require.ErrorIs(t, err, ErrNotSelfSigned)

	// The skipped errors are what SkippedCertificates hands back, without any ErrExpired
	_, err = NewCAPoolFromPEM(appendByteSlices(caPEM, expiredPEM, newVersionPEM, newCurvePEM))
	skipped := SkippedCertificates(err)
	require.Len(t, skipped, 2)
	require.ErrorIs(t, skipped[0], ErrUnknownVersion)
	require.ErrorIs(t, skipped[1], ErrUnknownCurve)
	require.ErrorContains(t, skipped[0], "certificate 3: ")
	require.ErrorContains(t, skipped[1], "certificate 4: ")
	assert.Nil(t, SkippedCertificates(ErrExpired))
	assert.Nil(t, SkippedCertificates(nil))
}

func TestCAPool_AddCAUnknownCurve(t *testing.T) {
	ca, _, _, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	c := ca.Copy().(*certificateV2)
	c.curve = Curve(2)

	err := NewCAPool().AddCA(c)
	require.ErrorIs(t, err, ErrUnknownCurve)
	require.EqualError(t, err, fmt.Sprintf("%q: certificate curve unrecognized: 2", c.Name()))
}

// A CA's name comes from the certificate, it is quoted so it can't inject control sequences into an error
func TestCAPool_AddCAQuotesName(t *testing.T) {
	ca, _, _, _ := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil)
	c := ca.Copy().(*certificateV2)
	c.details.name = "evil\x1b[31m\n"
	c.details.isCA = false

	err := NewCAPool().AddCA(c)
	require.ErrorIs(t, err, ErrNotCA)
	require.EqualError(t, err, `"evil\x1b[31m\n": certificate is not a CA`)
}

// A CA near MaxCertificateSize is larger than a bufio.Scanner holds by default as PEM
func TestNewCAPoolFromPEM_LargeCertificate(t *testing.T) {
	var groups []string
	for i := 0; len(groups)*20 < MaxCertificateSize-4096; i++ {
		groups = append(groups, fmt.Sprintf("group-%013d", i))
	}
	ca, _, _, caPEM := NewTestCaCert(Version2, Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, groups)
	require.Greater(t, len(caPEM), bufio.MaxScanTokenSize)
	fp, err := ca.Fingerprint()
	require.NoError(t, err)

	pool, err := NewCAPoolFromPEM(caPEM)
	require.NoError(t, err)
	assert.Contains(t, pool.CAs, fp)
}

// oneByteReader wraps a reader to return at most 1 byte per Read call,
// exercising the streaming accumulation logic in NewCAPoolFromPEMReader.
type oneByteReader struct {
	r io.Reader
}

func (o *oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

func TestNewCAPoolFromPEMReader_EmptyReader(t *testing.T) {
	pool, err := NewCAPoolFromPEMReader(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Empty(t, pool.CAs)

	pool, err = NewCAPoolFromPEMReader(strings.NewReader("   \n\t\n  "))
	require.NoError(t, err)
	assert.Empty(t, pool.CAs)
}

func TestNewCAPoolFromPEMReader_OneByteReads(t *testing.T) {
	ca1, _, _, pem1 := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(time.Hour), nil, nil, nil)
	ca2, _, _, pem2 := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(time.Hour), nil, nil, nil)

	bundle := append(pem1, pem2...)
	pool, err := NewCAPoolFromPEMReader(&oneByteReader{r: bytes.NewReader(bundle)})
	require.NoError(t, err)
	assert.Len(t, pool.CAs, 2)

	fp1, err := ca1.Fingerprint()
	require.NoError(t, err)
	fp2, err := ca2.Fingerprint()
	require.NoError(t, err)

	assert.Contains(t, pool.CAs, fp1)
	assert.Contains(t, pool.CAs, fp2)
}

func TestNewCAPoolFromPEMReader_TruncatedPEM(t *testing.T) {
	_, err := NewCAPoolFromPEMReader(strings.NewReader("-----BEGIN NEBULA CERTIFICATE-----\npartialdata"))
	assert.ErrorIs(t, err, ErrInvalidPEMBlock)
}

func TestNewCAPoolFromPEMReader_TrailingGarbage(t *testing.T) {
	_, _, _, pem1 := NewTestCaCert(Version2, Curve_CURVE25519, time.Now(), time.Now().Add(time.Hour), nil, nil, nil)

	bundle := append(pem1, []byte("some trailing garbage")...)
	_, err := NewCAPoolFromPEMReader(bytes.NewReader(bundle))
	assert.ErrorIs(t, err, ErrInvalidPEMBlock)
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

	// Create a copy of the cert and swap to the alternate form for the signature
	nc := c.Copy()
	b, err := p256.Swap(c.Signature().Classical)
	require.NoError(t, err)
	require.NoError(t, nc.(*certificateV1).setSignature(b))

	_, err = caPool.VerifyCertificate(time.Now(), nc)
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
	b, err = caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version1, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	cc, err := caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Reset the blocklist and block the alternate form fingerprint
	caPool.ResetCertBlocklist()
	caPool.BlocklistFingerprint(cc.fingerprint2)
	err = caPool.VerifyCachedCertificate(time.Now(), cc)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	err = caPool.VerifyCachedCertificate(time.Now(), cc)
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

	// Create a copy of the cert and swap to the alternate form for the signature
	nc := c.Copy()
	b, err := p256.Swap(c.Signature().Classical)
	require.NoError(t, err)
	require.NoError(t, nc.(*certificateV2).setSignature(b))

	_, err = caPool.VerifyCertificate(time.Now(), nc)
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
	b, err = caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	assert.PanicsWithError(t, "certificate contained a group not present on the signing ca: bad", func() {
		NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1", "bad"})
	})

	c, _, _, _ = NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), nil, nil, []string{"test1"})
	cc, err := caPool.VerifyCertificate(time.Now(), c)
	require.NoError(t, err)

	// Reset the blocklist and block the alternate form fingerprint
	caPool.ResetCertBlocklist()
	caPool.BlocklistFingerprint(cc.fingerprint2)
	err = caPool.VerifyCachedCertificate(time.Now(), cc)
	require.EqualError(t, err, "certificate is in the block list")

	caPool.ResetCertBlocklist()
	err = caPool.VerifyCachedCertificate(time.Now(), cc)
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

func TestCertificateV2_CurveMismatch(t *testing.T) {
	caIp1 := mustParsePrefixUnmapped("10.0.0.0/16")
	caIp2 := mustParsePrefixUnmapped("192.168.0.0/24")
	ca, _, caKey, _ := NewTestCaCert(Version2, Curve_P256, time.Now(), time.Now().Add(10*time.Minute), []netip.Prefix{caIp1, caIp2}, nil, []string{"test"})

	caPem, err := ca.MarshalPEM()
	require.NoError(t, err)

	caPool := NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	require.NoError(t, err)
	assert.Empty(t, b)

	// ip is outside the network
	cIp1 := mustParsePrefixUnmapped("10.0.0.1/24")
	c, _, _, _ := NewTestCert(Version2, Curve_P256, ca, caKey, "test", time.Now(), time.Now().Add(5*time.Minute), []netip.Prefix{cIp1}, nil, []string{"test"})

	fp, _ := c.Fingerprint()
	_, err = caPool.verify(c, time.Now(), fp, c.Issuer())
	require.NoError(t, err)
	//
	c2 := c.(*certificateV2)
	c2.curve = Curve_CURVE25519
	fp, _ = c.Fingerprint()
	_, err = caPool.verify(c, time.Now(), fp, c.Issuer())
	require.Error(t, err)
}
