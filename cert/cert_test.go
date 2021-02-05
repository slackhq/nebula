package cert

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/slackhq/nebula/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func TestMarshalingNebulaCertificate(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	nc := NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name: "testing",
			Ips: []*net.IPNet{
				{IP: net.ParseIP("10.1.1.1"), Mask: net.IPMask(net.ParseIP("255.255.255.0"))},
				{IP: net.ParseIP("10.1.1.2"), Mask: net.IPMask(net.ParseIP("255.255.0.0"))},
				{IP: net.ParseIP("10.1.1.3"), Mask: net.IPMask(net.ParseIP("255.0.255.0"))},
			},
			Subnets: []*net.IPNet{
				{IP: net.ParseIP("9.1.1.1"), Mask: net.IPMask(net.ParseIP("255.0.255.0"))},
				{IP: net.ParseIP("9.1.1.2"), Mask: net.IPMask(net.ParseIP("255.255.255.0"))},
				{IP: net.ParseIP("9.1.1.3"), Mask: net.IPMask(net.ParseIP("255.255.0.0"))},
			},
			Groups:    []string{"test-group1", "test-group2", "test-group3"},
			NotBefore: before,
			NotAfter:  after,
			PublicKey: pubKey,
			IsCA:      false,
			Issuer:    "1234567890abcedfghij1234567890ab",
		},
		Signature: []byte("1234567890abcedfghij1234567890ab"),
	}

	b, err := nc.Marshal()
	assert.Nil(t, err)
	//t.Log("Cert size:", len(b))

	nc2, err := UnmarshalNebulaCertificate(b)
	assert.Nil(t, err)

	assert.Equal(t, nc.Signature, nc2.Signature)
	assert.Equal(t, nc.Details.Name, nc2.Details.Name)
	assert.Equal(t, nc.Details.NotBefore, nc2.Details.NotBefore)
	assert.Equal(t, nc.Details.NotAfter, nc2.Details.NotAfter)
	assert.Equal(t, nc.Details.PublicKey, nc2.Details.PublicKey)
	assert.Equal(t, nc.Details.IsCA, nc2.Details.IsCA)

	// IP byte arrays can be 4 or 16 in length so we have to go this route
	assert.Equal(t, len(nc.Details.Ips), len(nc2.Details.Ips))
	for i, wIp := range nc.Details.Ips {
		assert.Equal(t, wIp.String(), nc2.Details.Ips[i].String())
	}

	assert.Equal(t, len(nc.Details.Subnets), len(nc2.Details.Subnets))
	for i, wIp := range nc.Details.Subnets {
		assert.Equal(t, wIp.String(), nc2.Details.Subnets[i].String())
	}

	assert.EqualValues(t, nc.Details.Groups, nc2.Details.Groups)
}

func TestNebulaCertificate_Sign(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	nc := NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name: "testing",
			Ips: []*net.IPNet{
				{IP: net.ParseIP("10.1.1.1"), Mask: net.IPMask(net.ParseIP("255.255.255.0"))},
				{IP: net.ParseIP("10.1.1.2"), Mask: net.IPMask(net.ParseIP("255.255.0.0"))},
				{IP: net.ParseIP("10.1.1.3"), Mask: net.IPMask(net.ParseIP("255.0.255.0"))},
			},
			Subnets: []*net.IPNet{
				{IP: net.ParseIP("9.1.1.1"), Mask: net.IPMask(net.ParseIP("255.0.255.0"))},
				{IP: net.ParseIP("9.1.1.2"), Mask: net.IPMask(net.ParseIP("255.255.255.0"))},
				{IP: net.ParseIP("9.1.1.3"), Mask: net.IPMask(net.ParseIP("255.255.0.0"))},
			},
			Groups:    []string{"test-group1", "test-group2", "test-group3"},
			NotBefore: before,
			NotAfter:  after,
			PublicKey: pubKey,
			IsCA:      false,
			Issuer:    "1234567890abcedfghij1234567890ab",
		},
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	assert.False(t, nc.CheckSignature(pub))
	assert.Nil(t, nc.Sign(priv))
	assert.True(t, nc.CheckSignature(pub))

	_, err = nc.Marshal()
	assert.Nil(t, err)
	//t.Log("Cert size:", len(b))
}

func TestNebulaCertificate_Expired(t *testing.T) {
	nc := NebulaCertificate{
		Details: NebulaCertificateDetails{
			NotBefore: time.Now().Add(time.Second * -60).Round(time.Second),
			NotAfter:  time.Now().Add(time.Second * 60).Round(time.Second),
		},
	}

	assert.True(t, nc.Expired(time.Now().Add(time.Hour)))
	assert.True(t, nc.Expired(time.Now().Add(-time.Hour)))
	assert.False(t, nc.Expired(time.Now()))
}

func TestNebulaCertificate_MarshalJSON(t *testing.T) {
	time.Local = time.UTC
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	nc := NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name: "testing",
			Ips: []*net.IPNet{
				{IP: net.ParseIP("10.1.1.1"), Mask: net.IPMask(net.ParseIP("255.255.255.0"))},
				{IP: net.ParseIP("10.1.1.2"), Mask: net.IPMask(net.ParseIP("255.255.0.0"))},
				{IP: net.ParseIP("10.1.1.3"), Mask: net.IPMask(net.ParseIP("255.0.255.0"))},
			},
			Subnets: []*net.IPNet{
				{IP: net.ParseIP("9.1.1.1"), Mask: net.IPMask(net.ParseIP("255.0.255.0"))},
				{IP: net.ParseIP("9.1.1.2"), Mask: net.IPMask(net.ParseIP("255.255.255.0"))},
				{IP: net.ParseIP("9.1.1.3"), Mask: net.IPMask(net.ParseIP("255.255.0.0"))},
			},
			Groups:    []string{"test-group1", "test-group2", "test-group3"},
			NotBefore: time.Date(1, 0, 0, 1, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(1, 0, 0, 2, 0, 0, 0, time.UTC),
			PublicKey: pubKey,
			IsCA:      false,
			Issuer:    "1234567890abcedfghij1234567890ab",
		},
		Signature: []byte("1234567890abcedfghij1234567890ab"),
	}

	b, err := nc.MarshalJSON()
	assert.Nil(t, err)
	assert.Equal(
		t,
		"{\"details\":{\"groups\":[\"test-group1\",\"test-group2\",\"test-group3\"],\"ips\":[\"10.1.1.1/24\",\"10.1.1.2/16\",\"10.1.1.3/ff00ff00\"],\"isCa\":false,\"issuer\":\"1234567890abcedfghij1234567890ab\",\"name\":\"testing\",\"notAfter\":\"0000-11-30T02:00:00Z\",\"notBefore\":\"0000-11-30T01:00:00Z\",\"publicKey\":\"313233343536373839306162636564666768696a313233343536373839306162\",\"subnets\":[\"9.1.1.1/ff00ff00\",\"9.1.1.2/24\",\"9.1.1.3/16\"]},\"fingerprint\":\"26cb1c30ad7872c804c166b5150fa372f437aa3856b04edb4334b4470ec728e4\",\"signature\":\"313233343536373839306162636564666768696a313233343536373839306162\"}",
		string(b),
	)
}

func TestNebulaCertificate_Verify(t *testing.T) {
	ca, _, caKey, err := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)

	c, _, _, err := newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)

	h, err := ca.Sha256Sum()
	assert.Nil(t, err)

	caPool := NewCAPool()
	caPool.CAs[h] = ca

	f, err := c.Sha256Sum()
	assert.Nil(t, err)
	caPool.BlocklistFingerprint(f)

	v, err := c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate has been blocked")

	caPool.ResetCertBlocklist()
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)

	v, err = c.Verify(time.Now().Add(time.Hour*1000), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "root certificate is expired")

	c, _, _, err = newTestCert(ca, caKey, time.Time{}, time.Time{}, []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now().Add(time.Minute*6), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate is expired")

	// Test group assertion
	ca, _, caKey, err = newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{"test1", "test2"})
	assert.Nil(t, err)

	caPem, err := ca.MarshalToPEM()
	assert.Nil(t, err)

	caPool = NewCAPool()
	caPool.AddCACertificate(caPem)

	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{"test1", "bad"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate contained a group not present on the signing ca: bad")

	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{"test1"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)
}

func TestNebulaCertificate_Verify_IPs(t *testing.T) {
	_, caIp1, _ := net.ParseCIDR("10.0.0.0/16")
	_, caIp2, _ := net.ParseCIDR("192.168.0.0/24")
	ca, _, caKey, err := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{caIp1, caIp2}, []*net.IPNet{}, []string{"test"})
	assert.Nil(t, err)

	caPem, err := ca.MarshalToPEM()
	assert.Nil(t, err)

	caPool := NewCAPool()
	caPool.AddCACertificate(caPem)

	// ip is outside the network
	cIp1 := &net.IPNet{IP: net.ParseIP("10.1.0.0"), Mask: []byte{255, 255, 255, 0}}
	cIp2 := &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 0, 0}}
	c, _, _, err := newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{cIp1, cIp2}, []*net.IPNet{}, []string{"test"})
	assert.Nil(t, err)
	v, err := c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate contained an ip assignment outside the limitations of the signing ca: 10.1.0.0/24")

	// ip is outside the network reversed order of above
	cIp1 = &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 255, 0}}
	cIp2 = &net.IPNet{IP: net.ParseIP("10.1.0.0"), Mask: []byte{255, 255, 255, 0}}
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{cIp1, cIp2}, []*net.IPNet{}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate contained an ip assignment outside the limitations of the signing ca: 10.1.0.0/24")

	// ip is within the network but mask is outside
	cIp1 = &net.IPNet{IP: net.ParseIP("10.0.1.0"), Mask: []byte{255, 254, 0, 0}}
	cIp2 = &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 255, 0}}
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{cIp1, cIp2}, []*net.IPNet{}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate contained an ip assignment outside the limitations of the signing ca: 10.0.1.0/15")

	// ip is within the network but mask is outside reversed order of above
	cIp1 = &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 255, 0}}
	cIp2 = &net.IPNet{IP: net.ParseIP("10.0.1.0"), Mask: []byte{255, 254, 0, 0}}
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{cIp1, cIp2}, []*net.IPNet{}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate contained an ip assignment outside the limitations of the signing ca: 10.0.1.0/15")

	// ip and mask are within the network
	cIp1 = &net.IPNet{IP: net.ParseIP("10.0.1.0"), Mask: []byte{255, 255, 0, 0}}
	cIp2 = &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 255, 128}}
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{cIp1, cIp2}, []*net.IPNet{}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)

	// Exact matches
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{caIp1, caIp2}, []*net.IPNet{}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)

	// Exact matches reversed
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{caIp2, caIp1}, []*net.IPNet{}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)

	// Exact matches reversed with just 1
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{caIp1}, []*net.IPNet{}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)
}

func TestNebulaCertificate_Verify_Subnets(t *testing.T) {
	_, caIp1, _ := net.ParseCIDR("10.0.0.0/16")
	_, caIp2, _ := net.ParseCIDR("192.168.0.0/24")
	ca, _, caKey, err := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{caIp1, caIp2}, []string{"test"})
	assert.Nil(t, err)

	caPem, err := ca.MarshalToPEM()
	assert.Nil(t, err)

	caPool := NewCAPool()
	caPool.AddCACertificate(caPem)

	// ip is outside the network
	cIp1 := &net.IPNet{IP: net.ParseIP("10.1.0.0"), Mask: []byte{255, 255, 255, 0}}
	cIp2 := &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 0, 0}}
	c, _, _, err := newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{cIp1, cIp2}, []string{"test"})
	assert.Nil(t, err)
	v, err := c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate contained a subnet assignment outside the limitations of the signing ca: 10.1.0.0/24")

	// ip is outside the network reversed order of above
	cIp1 = &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 255, 0}}
	cIp2 = &net.IPNet{IP: net.ParseIP("10.1.0.0"), Mask: []byte{255, 255, 255, 0}}
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{cIp1, cIp2}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate contained a subnet assignment outside the limitations of the signing ca: 10.1.0.0/24")

	// ip is within the network but mask is outside
	cIp1 = &net.IPNet{IP: net.ParseIP("10.0.1.0"), Mask: []byte{255, 254, 0, 0}}
	cIp2 = &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 255, 0}}
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{cIp1, cIp2}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate contained a subnet assignment outside the limitations of the signing ca: 10.0.1.0/15")

	// ip is within the network but mask is outside reversed order of above
	cIp1 = &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 255, 0}}
	cIp2 = &net.IPNet{IP: net.ParseIP("10.0.1.0"), Mask: []byte{255, 254, 0, 0}}
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{cIp1, cIp2}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.False(t, v)
	assert.EqualError(t, err, "certificate contained a subnet assignment outside the limitations of the signing ca: 10.0.1.0/15")

	// ip and mask are within the network
	cIp1 = &net.IPNet{IP: net.ParseIP("10.0.1.0"), Mask: []byte{255, 255, 0, 0}}
	cIp2 = &net.IPNet{IP: net.ParseIP("192.168.0.1"), Mask: []byte{255, 255, 255, 128}}
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{cIp1, cIp2}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)

	// Exact matches
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{caIp1, caIp2}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)

	// Exact matches reversed
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{caIp2, caIp1}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)

	// Exact matches reversed with just 1
	c, _, _, err = newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{caIp1}, []string{"test"})
	assert.Nil(t, err)
	v, err = c.Verify(time.Now(), caPool)
	assert.True(t, v)
	assert.Nil(t, err)
}

func TestNebulaVerifyPrivateKey(t *testing.T) {
	ca, _, caKey, err := newTestCaCert(time.Time{}, time.Time{}, []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)

	c, _, priv, err := newTestCert(ca, caKey, time.Time{}, time.Time{}, []*net.IPNet{}, []*net.IPNet{}, []string{})
	err = c.VerifyPrivateKey(priv)
	assert.Nil(t, err)

	_, priv2 := x25519Keypair()
	err = c.VerifyPrivateKey(priv2)
	assert.NotNil(t, err)
}

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

	rootCA := NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name: "nebula root ca",
		},
	}

	rootCA01 := NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name: "nebula root ca 01",
		},
	}

	p, err := NewCAPoolFromBytes([]byte(noNewLines))
	assert.Nil(t, err)
	assert.Equal(t, p.CAs[string("c9bfaf7ce8e84b2eeda2e27b469f4b9617bde192efd214b68891ecda6ed49522")].Details.Name, rootCA.Details.Name)
	assert.Equal(t, p.CAs[string("5c9c3f23e7ee7fe97637cbd3a0a5b854154d1d9aaaf7b566a51f4a88f76b64cd")].Details.Name, rootCA01.Details.Name)

	pp, err := NewCAPoolFromBytes([]byte(withNewLines))
	assert.Nil(t, err)
	assert.Equal(t, pp.CAs[string("c9bfaf7ce8e84b2eeda2e27b469f4b9617bde192efd214b68891ecda6ed49522")].Details.Name, rootCA.Details.Name)
	assert.Equal(t, pp.CAs[string("5c9c3f23e7ee7fe97637cbd3a0a5b854154d1d9aaaf7b566a51f4a88f76b64cd")].Details.Name, rootCA01.Details.Name)
}

func appendByteSlices(b ...[]byte) []byte {
	retSlice := []byte{}
	for _, v := range b {
		retSlice = append(retSlice, v...)
	}
	return retSlice
}

func TestUnmrshalCertPEM(t *testing.T) {
	goodCert := []byte(`
# A good cert
-----BEGIN NEBULA CERTIFICATE-----
CkAKDm5lYnVsYSByb290IGNhKJfap9AFMJfg1+YGOiCUQGByMuNRhIlQBOyzXWbL
vcKBwDhov900phEfJ5DN3kABEkDCq5R8qBiu8sl54yVfgRcQXEDt3cHr8UTSLszv
bzBEr00kERQxxTzTsH8cpYEgRoipvmExvg8WP8NdAJEYJosB
-----END NEBULA CERTIFICATE-----
`)
	badBanner := []byte(`# A bad banner
-----BEGIN NOT A NEBULA CERTIFICATE-----
CkAKDm5lYnVsYSByb290IGNhKJfap9AFMJfg1+YGOiCUQGByMuNRhIlQBOyzXWbL
vcKBwDhov900phEfJ5DN3kABEkDCq5R8qBiu8sl54yVfgRcQXEDt3cHr8UTSLszv
bzBEr00kERQxxTzTsH8cpYEgRoipvmExvg8WP8NdAJEYJosB
-----END NOT A NEBULA CERTIFICATE-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA CERTIFICATE-----
CkAKDm5lYnVsYSByb290IGNhKJfap9AFMJfg1+YGOiCUQGByMuNRhIlQBOyzXWbL
vcKBwDhov900phEfJ5DN3kABEkDCq5R8qBiu8sl54yVfgRcQXEDt3cHr8UTSLszv
bzBEr00kERQxxTzTsH8cpYEgRoipvmExvg8WP8NdAJEYJosB
-END NEBULA CERTIFICATE----`)

	certBundle := appendByteSlices(goodCert, badBanner, invalidPem)

	// Success test case
	cert, rest, err := UnmarshalNebulaCertificateFromPEM(certBundle)
	assert.NotNil(t, cert)
	assert.Equal(t, rest, append(badBanner, invalidPem...))
	assert.Nil(t, err)

	// Fail due to invalid banner.
	cert, rest, err = UnmarshalNebulaCertificateFromPEM(rest)
	assert.Nil(t, cert)
	assert.Equal(t, rest, invalidPem)
	assert.EqualError(t, err, "bytes did not contain a proper nebula certificate banner")

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	cert, rest, err = UnmarshalNebulaCertificateFromPEM(rest)
	assert.Nil(t, cert)
	assert.Equal(t, rest, invalidPem)
	assert.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalEd25519PrivateKey(t *testing.T) {
	privKey := []byte(`# A good key
-----BEGIN NEBULA ED25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NEBULA ED25519 PRIVATE KEY-----
`)
	shortKey := []byte(`# A short key
-----BEGIN NEBULA ED25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END NEBULA ED25519 PRIVATE KEY-----
`)
	invalidBanner := []byte(`# Invalid banner
-----BEGIN NOT A NEBULA PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NOT A NEBULA PRIVATE KEY-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA ED25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-END NEBULA ED25519 PRIVATE KEY-----`)

	keyBundle := appendByteSlices(privKey, shortKey, invalidBanner, invalidPem)

	// Success test case
	k, rest, err := UnmarshalEd25519PrivateKey(keyBundle)
	assert.Len(t, k, 64)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))
	assert.Nil(t, err)

	// Fail due to short key
	k, rest, err = UnmarshalEd25519PrivateKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	assert.EqualError(t, err, "key was not 64 bytes, is invalid ed25519 private key")

	// Fail due to invalid banner
	k, rest, err = UnmarshalEd25519PrivateKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	assert.EqualError(t, err, "bytes did not contain a proper nebula Ed25519 private key banner")

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, err = UnmarshalEd25519PrivateKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	assert.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalX25519PrivateKey(t *testing.T) {
	privKey := []byte(`# A good key
-----BEGIN NEBULA X25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA X25519 PRIVATE KEY-----
`)
	shortKey := []byte(`# A short key
-----BEGIN NEBULA X25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NEBULA X25519 PRIVATE KEY-----
`)
	invalidBanner := []byte(`# Invalid banner
-----BEGIN NOT A NEBULA PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NOT A NEBULA PRIVATE KEY-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA X25519 PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-END NEBULA X25519 PRIVATE KEY-----`)

	keyBundle := appendByteSlices(privKey, shortKey, invalidBanner, invalidPem)

	// Success test case
	k, rest, err := UnmarshalX25519PrivateKey(keyBundle)
	assert.Len(t, k, 32)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))
	assert.Nil(t, err)

	// Fail due to short key
	k, rest, err = UnmarshalX25519PrivateKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	assert.EqualError(t, err, "key was not 32 bytes, is invalid X25519 private key")

	// Fail due to invalid banner
	k, rest, err = UnmarshalX25519PrivateKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	assert.EqualError(t, err, "bytes did not contain a proper nebula X25519 private key banner")

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, err = UnmarshalX25519PrivateKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	assert.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalEd25519PublicKey(t *testing.T) {
	pubKey := []byte(`# A good key
-----BEGIN NEBULA ED25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA ED25519 PUBLIC KEY-----
`)
	shortKey := []byte(`# A short key
-----BEGIN NEBULA ED25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NEBULA ED25519 PUBLIC KEY-----
`)
	invalidBanner := []byte(`# Invalid banner
-----BEGIN NOT A NEBULA PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NOT A NEBULA PUBLIC KEY-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA ED25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-END NEBULA ED25519 PUBLIC KEY-----`)

	keyBundle := appendByteSlices(pubKey, shortKey, invalidBanner, invalidPem)

	// Success test case
	k, rest, err := UnmarshalEd25519PublicKey(keyBundle)
	assert.Equal(t, len(k), 32)
	assert.Nil(t, err)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))

	// Fail due to short key
	k, rest, err = UnmarshalEd25519PublicKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	assert.EqualError(t, err, "key was not 32 bytes, is invalid ed25519 public key")

	// Fail due to invalid banner
	k, rest, err = UnmarshalEd25519PublicKey(rest)
	assert.Nil(t, k)
	assert.EqualError(t, err, "bytes did not contain a proper nebula Ed25519 public key banner")
	assert.Equal(t, rest, invalidPem)

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, err = UnmarshalEd25519PublicKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	assert.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

func TestUnmarshalX25519PublicKey(t *testing.T) {
	pubKey := []byte(`# A good key
-----BEGIN NEBULA X25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NEBULA X25519 PUBLIC KEY-----
`)
	shortKey := []byte(`# A short key
-----BEGIN NEBULA X25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END NEBULA X25519 PUBLIC KEY-----
`)
	invalidBanner := []byte(`# Invalid banner
-----BEGIN NOT A NEBULA PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END NOT A NEBULA PUBLIC KEY-----
`)
	invalidPem := []byte(`# Not a valid PEM format
-BEGIN NEBULA X25519 PUBLIC KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-END NEBULA X25519 PUBLIC KEY-----`)

	keyBundle := appendByteSlices(pubKey, shortKey, invalidBanner, invalidPem)

	// Success test case
	k, rest, err := UnmarshalX25519PublicKey(keyBundle)
	assert.Equal(t, len(k), 32)
	assert.Nil(t, err)
	assert.Equal(t, rest, appendByteSlices(shortKey, invalidBanner, invalidPem))

	// Fail due to short key
	k, rest, err = UnmarshalX25519PublicKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, appendByteSlices(invalidBanner, invalidPem))
	assert.EqualError(t, err, "key was not 32 bytes, is invalid X25519 public key")

	// Fail due to invalid banner
	k, rest, err = UnmarshalX25519PublicKey(rest)
	assert.Nil(t, k)
	assert.EqualError(t, err, "bytes did not contain a proper nebula X25519 public key banner")
	assert.Equal(t, rest, invalidPem)

	// Fail due to ivalid PEM format, because
	// it's missing the requisite pre-encapsulation boundary.
	k, rest, err = UnmarshalX25519PublicKey(rest)
	assert.Nil(t, k)
	assert.Equal(t, rest, invalidPem)
	assert.EqualError(t, err, "input did not contain a valid PEM encoded block")
}

// Ensure that upgrading the protobuf library does not change how certificates
// are marshalled, since this would break signature verification
func TestMarshalingNebulaCertificateConsistency(t *testing.T) {
	before := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	after := time.Date(2017, time.January, 18, 28, 40, 0, 0, time.UTC)
	pubKey := []byte("1234567890abcedfghij1234567890ab")

	nc := NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name: "testing",
			Ips: []*net.IPNet{
				{IP: net.ParseIP("10.1.1.1"), Mask: net.IPMask(net.ParseIP("255.255.255.0"))},
				{IP: net.ParseIP("10.1.1.2"), Mask: net.IPMask(net.ParseIP("255.255.0.0"))},
				{IP: net.ParseIP("10.1.1.3"), Mask: net.IPMask(net.ParseIP("255.0.255.0"))},
			},
			Subnets: []*net.IPNet{
				{IP: net.ParseIP("9.1.1.1"), Mask: net.IPMask(net.ParseIP("255.0.255.0"))},
				{IP: net.ParseIP("9.1.1.2"), Mask: net.IPMask(net.ParseIP("255.255.255.0"))},
				{IP: net.ParseIP("9.1.1.3"), Mask: net.IPMask(net.ParseIP("255.255.0.0"))},
			},
			Groups:    []string{"test-group1", "test-group2", "test-group3"},
			NotBefore: before,
			NotAfter:  after,
			PublicKey: pubKey,
			IsCA:      false,
			Issuer:    "1234567890abcedfghij1234567890ab",
		},
		Signature: []byte("1234567890abcedfghij1234567890ab"),
	}

	b, err := nc.Marshal()
	assert.Nil(t, err)
	//t.Log("Cert size:", len(b))
	assert.Equal(t, "0aa2010a0774657374696e67121b8182845080feffff0f828284508080fcff0f8382845080fe83f80f1a1b8182844880fe83f80f8282844880feffff0f838284488080fcff0f220b746573742d67726f757031220b746573742d67726f757032220b746573742d67726f75703328f0e0e7d70430a08681c4053a20313233343536373839306162636564666768696a3132333435363738393061624a081234567890abcedf1220313233343536373839306162636564666768696a313233343536373839306162", fmt.Sprintf("%x", b))

	b, err = proto.Marshal(nc.getRawDetails())
	assert.Nil(t, err)
	//t.Log("Raw cert size:", len(b))
	assert.Equal(t, "0a0774657374696e67121b8182845080feffff0f828284508080fcff0f8382845080fe83f80f1a1b8182844880fe83f80f8282844880feffff0f838284488080fcff0f220b746573742d67726f757031220b746573742d67726f757032220b746573742d67726f75703328f0e0e7d70430a08681c4053a20313233343536373839306162636564666768696a3132333435363738393061624a081234567890abcedf", fmt.Sprintf("%x", b))
}

func TestNebulaCertificate_Copy(t *testing.T) {
	ca, _, caKey, err := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)

	c, _, _, err := newTestCert(ca, caKey, time.Now(), time.Now().Add(5*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)
	cc := c.Copy()

	util.AssertDeepCopyEqual(t, c, cc)
}

func TestUnmarshalNebulaCertificate(t *testing.T) {
	// Test that we don't panic with an invalid certificate (#332)
	data := []byte("\x98\x00\x00")
	_, err := UnmarshalNebulaCertificate(data)
	assert.EqualError(t, err, "encoded Details was nil")
}

func newTestCaCert(before, after time.Time, ips, subnets []*net.IPNet, groups []string) (*NebulaCertificate, []byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	nc := &NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name:           "test ca",
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           true,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	if len(ips) > 0 {
		nc.Details.Ips = ips
	}

	if len(subnets) > 0 {
		nc.Details.Subnets = subnets
	}

	if len(groups) > 0 {
		nc.Details.Groups = groups
	}

	err = nc.Sign(priv)
	if err != nil {
		return nil, nil, nil, err
	}
	return nc, pub, priv, nil
}

func newTestCert(ca *NebulaCertificate, key []byte, before, after time.Time, ips, subnets []*net.IPNet, groups []string) (*NebulaCertificate, []byte, []byte, error) {
	issuer, err := ca.Sha256Sum()
	if err != nil {
		return nil, nil, nil, err
	}

	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	if len(groups) == 0 {
		groups = []string{"test-group1", "test-group2", "test-group3"}
	}

	if len(ips) == 0 {
		ips = []*net.IPNet{
			{IP: net.ParseIP("10.1.1.1").To4(), Mask: net.IPMask(net.ParseIP("255.255.255.0").To4())},
			{IP: net.ParseIP("10.1.1.2").To4(), Mask: net.IPMask(net.ParseIP("255.255.0.0").To4())},
			{IP: net.ParseIP("10.1.1.3").To4(), Mask: net.IPMask(net.ParseIP("255.0.255.0").To4())},
		}
	}

	if len(subnets) == 0 {
		subnets = []*net.IPNet{
			{IP: net.ParseIP("9.1.1.1").To4(), Mask: net.IPMask(net.ParseIP("255.0.255.0").To4())},
			{IP: net.ParseIP("9.1.1.2").To4(), Mask: net.IPMask(net.ParseIP("255.255.255.0").To4())},
			{IP: net.ParseIP("9.1.1.3").To4(), Mask: net.IPMask(net.ParseIP("255.255.0.0").To4())},
		}
	}

	pub, rawPriv := x25519Keypair()

	nc := &NebulaCertificate{
		Details: NebulaCertificateDetails{
			Name:           "testing",
			Ips:            ips,
			Subnets:        subnets,
			Groups:         groups,
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           false,
			Issuer:         issuer,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	err = nc.Sign(key)
	if err != nil {
		return nil, nil, nil, err
	}

	return nc, pub, rawPriv, nil
}

func x25519Keypair() ([]byte, []byte) {
	var pubkey, privkey [32]byte
	if _, err := io.ReadFull(rand.Reader, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return pubkey[:], privkey[:]
}
