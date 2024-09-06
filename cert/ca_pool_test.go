package cert

import (
	"testing"

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
			Name: "nebula root ca",
		},
	}

	rootCA01 := certificateV1{
		details: detailsV1{
			Name: "nebula root ca 01",
		},
	}

	rootCAP256 := certificateV1{
		details: detailsV1{
			Name: "nebula P256 test",
		},
	}

	p, err := NewCAPoolFromPEM([]byte(noNewLines))
	assert.Nil(t, err)
	assert.Equal(t, p.CAs[string("c9bfaf7ce8e84b2eeda2e27b469f4b9617bde192efd214b68891ecda6ed49522")].Certificate.Name(), rootCA.details.Name)
	assert.Equal(t, p.CAs[string("5c9c3f23e7ee7fe97637cbd3a0a5b854154d1d9aaaf7b566a51f4a88f76b64cd")].Certificate.Name(), rootCA01.details.Name)

	pp, err := NewCAPoolFromPEM([]byte(withNewLines))
	assert.Nil(t, err)
	assert.Equal(t, pp.CAs[string("c9bfaf7ce8e84b2eeda2e27b469f4b9617bde192efd214b68891ecda6ed49522")].Certificate.Name(), rootCA.details.Name)
	assert.Equal(t, pp.CAs[string("5c9c3f23e7ee7fe97637cbd3a0a5b854154d1d9aaaf7b566a51f4a88f76b64cd")].Certificate.Name(), rootCA01.details.Name)

	// expired cert, no valid certs
	ppp, err := NewCAPoolFromPEM([]byte(expired))
	assert.Equal(t, ErrExpired, err)
	assert.Equal(t, ppp.CAs[string("152070be6bb19bc9e3bde4c2f0e7d8f4ff5448b4c9856b8eccb314fade0229b0")].Certificate.Name(), "expired")

	// expired cert, with valid certs
	pppp, err := NewCAPoolFromPEM(append([]byte(expired), noNewLines...))
	assert.Equal(t, ErrExpired, err)
	assert.Equal(t, pppp.CAs[string("c9bfaf7ce8e84b2eeda2e27b469f4b9617bde192efd214b68891ecda6ed49522")].Certificate.Name(), rootCA.details.Name)
	assert.Equal(t, pppp.CAs[string("5c9c3f23e7ee7fe97637cbd3a0a5b854154d1d9aaaf7b566a51f4a88f76b64cd")].Certificate.Name(), rootCA01.details.Name)
	assert.Equal(t, pppp.CAs[string("152070be6bb19bc9e3bde4c2f0e7d8f4ff5448b4c9856b8eccb314fade0229b0")].Certificate.Name(), "expired")
	assert.Equal(t, len(pppp.CAs), 3)

	ppppp, err := NewCAPoolFromPEM([]byte(p256))
	assert.Nil(t, err)
	assert.Equal(t, ppppp.CAs[string("a7938893ec8c4ef769b06d7f425e5e46f7a7f5ffa49c3bcf4a86b608caba9159")].Certificate.Name(), rootCAP256.details.Name)
	assert.Equal(t, len(ppppp.CAs), 1)
}
