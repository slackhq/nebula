package cert

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/proto"
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
	assert.Nil(t, nc.Sign(Curve_CURVE25519, priv))
	assert.True(t, nc.CheckSignature(pub))

	_, err = nc.Marshal()
	assert.Nil(t, err)
	//t.Log("Cert size:", len(b))
}

func TestNebulaCertificate_SignP256(t *testing.T) {
	before := time.Now().Add(time.Second * -60).Round(time.Second)
	after := time.Now().Add(time.Second * 60).Round(time.Second)
	pubKey := []byte("01234567890abcedfghij1234567890ab1234567890abcedfghij1234567890ab")

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
			Curve:     Curve_P256,
			Issuer:    "1234567890abcedfghij1234567890ab",
		},
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	rawPriv := priv.D.FillBytes(make([]byte, 32))

	assert.Nil(t, err)
	assert.False(t, nc.CheckSignature(pub))
	assert.Nil(t, nc.Sign(Curve_P256, rawPriv))
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
		"{\"details\":{\"curve\":\"CURVE25519\",\"groups\":[\"test-group1\",\"test-group2\",\"test-group3\"],\"ips\":[\"10.1.1.1/24\",\"10.1.1.2/16\",\"10.1.1.3/ff00ff00\"],\"isCa\":false,\"issuer\":\"1234567890abcedfghij1234567890ab\",\"name\":\"testing\",\"notAfter\":\"0000-11-30T02:00:00Z\",\"notBefore\":\"0000-11-30T01:00:00Z\",\"publicKey\":\"313233343536373839306162636564666768696a313233343536373839306162\",\"subnets\":[\"9.1.1.1/ff00ff00\",\"9.1.1.2/24\",\"9.1.1.3/16\"]},\"fingerprint\":\"26cb1c30ad7872c804c166b5150fa372f437aa3856b04edb4334b4470ec728e4\",\"signature\":\"313233343536373839306162636564666768696a313233343536373839306162\"}",
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
	assert.EqualError(t, err, "certificate is in the block list")

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
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
	assert.Empty(t, b)

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

func TestNebulaCertificate_VerifyP256(t *testing.T) {
	ca, _, caKey, err := newTestCaCertP256(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
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
	assert.EqualError(t, err, "certificate is in the block list")

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
	ca, _, caKey, err = newTestCaCertP256(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{"test1", "test2"})
	assert.Nil(t, err)

	caPem, err := ca.MarshalToPEM()
	assert.Nil(t, err)

	caPool = NewCAPool()
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
	assert.Empty(t, b)

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
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
	assert.Empty(t, b)

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
	b, err := caPool.AddCAFromPEM(caPem)
	assert.NoError(t, err)
	assert.Empty(t, b)

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

func TestNebulaCertificate_VerifyPrivateKey(t *testing.T) {
	ca, _, caKey, err := newTestCaCert(time.Time{}, time.Time{}, []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)
	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey)
	assert.Nil(t, err)

	_, _, caKey2, err := newTestCaCert(time.Time{}, time.Time{}, []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)
	err = ca.VerifyPrivateKey(Curve_CURVE25519, caKey2)
	assert.NotNil(t, err)

	c, _, priv, err := newTestCert(ca, caKey, time.Time{}, time.Time{}, []*net.IPNet{}, []*net.IPNet{}, []string{})
	err = c.VerifyPrivateKey(Curve_CURVE25519, priv)
	assert.Nil(t, err)

	_, priv2 := x25519Keypair()
	err = c.VerifyPrivateKey(Curve_CURVE25519, priv2)
	assert.NotNil(t, err)
}

func TestNebulaCertificate_VerifyPrivateKeyP256(t *testing.T) {
	ca, _, caKey, err := newTestCaCertP256(time.Time{}, time.Time{}, []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)
	err = ca.VerifyPrivateKey(Curve_P256, caKey)
	assert.Nil(t, err)

	_, _, caKey2, err := newTestCaCertP256(time.Time{}, time.Time{}, []*net.IPNet{}, []*net.IPNet{}, []string{})
	assert.Nil(t, err)
	err = ca.VerifyPrivateKey(Curve_P256, caKey2)
	assert.NotNil(t, err)

	c, _, priv, err := newTestCert(ca, caKey, time.Time{}, time.Time{}, []*net.IPNet{}, []*net.IPNet{}, []string{})
	err = c.VerifyPrivateKey(Curve_P256, priv)
	assert.Nil(t, err)

	_, priv2 := p256Keypair()
	err = c.VerifyPrivateKey(Curve_P256, priv2)
	assert.NotNil(t, err)
}

func appendByteSlices(b ...[]byte) []byte {
	retSlice := []byte{}
	for _, v := range b {
		retSlice = append(retSlice, v...)
	}
	return retSlice
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

	test.AssertDeepCopyEqual(t, c, cc)
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

	err = nc.Sign(Curve_CURVE25519, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	return nc, pub, priv, nil
}

func newTestCaCertP256(before, after time.Time, ips, subnets []*net.IPNet, groups []string) (*NebulaCertificate, []byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	rawPriv := priv.D.FillBytes(make([]byte, 32))

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
			Curve:          Curve_P256,
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

	err = nc.Sign(Curve_P256, rawPriv)
	if err != nil {
		return nil, nil, nil, err
	}
	return nc, pub, rawPriv, nil
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

	var pub, rawPriv []byte

	switch ca.Details.Curve {
	case Curve_CURVE25519:
		pub, rawPriv = x25519Keypair()
	case Curve_P256:
		pub, rawPriv = p256Keypair()
	default:
		return nil, nil, nil, fmt.Errorf("unknown curve: %v", ca.Details.Curve)
	}

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
			Curve:          ca.Details.Curve,
			Issuer:         issuer,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	err = nc.Sign(ca.Details.Curve, key)
	if err != nil {
		return nil, nil, nil, err
	}

	return nc, pub, rawPriv, nil
}

func x25519Keypair() ([]byte, []byte) {
	privkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		panic(err)
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return pubkey, privkey
}

func p256Keypair() ([]byte, []byte) {
	privkey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey := privkey.PublicKey()
	return pubkey.Bytes(), privkey.Bytes()
}
