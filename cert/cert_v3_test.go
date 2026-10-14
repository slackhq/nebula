package cert

import (
	"crypto/mldsa"
	"crypto/mlkem"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert/p256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var testCurves = []Curve{Curve_CURVE25519, Curve_P256}

func newTestV3(t *testing.T, curve Curve) (ca Certificate, caKey []byte, host Certificate, hostKey []byte) {
	t.Helper()
	ca, _, caKey, _ = NewTestCaCert(Version3, curve, time.Time{}, time.Time{}, nil, nil, []string{"g"})
	host, _, hostKeyPEM, _ := NewTestCert(Version3, curve, ca, caKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, []string{"g"})
	hostKey, _, _, err := UnmarshalPrivateKeyFromPEM(hostKeyPEM)
	require.NoError(t, err)
	return ca, caKey, host, hostKey
}

func TestCertificateV3_Sign(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host, hostKey := newTestV3(t, curve)
			assert.Equal(t, Version3, ca.Version())
			assert.Equal(t, Version3, host.Version())

			assert.True(t, ca.CheckSignature(ca.PublicKey()))
			assert.True(t, host.CheckSignature(ca.PublicKey()))
			require.NoError(t, ca.VerifyPrivateKey(curve, caKey))
			require.NoError(t, host.VerifyPrivateKey(curve, hostKey))

			// The classical half of the key alone is not the key.
			require.Error(t, host.VerifyPrivateKey(curve, hostKey[:len(hostKey)-MLKEM1024PrivateKeySize]))

			// The issuer is the v2 form of the CA, which old peers know it by.
			caV2Fp, err := V2Form(ca).Fingerprint()
			require.NoError(t, err)
			assert.Equal(t, caV2Fp, host.Issuer())

			// A v2 CA can not sign a v3 certificate, nor a v3 CA a v2 one.
			_, err = (&TBSCertificate{Version: Version3, Curve: curve, Name: "x", Networks: host.Networks(), NotBefore: host.NotBefore(), NotAfter: host.NotAfter(), PublicKey: host.PublicKey()}).Sign(V2Form(ca), curve, caKey)
			require.Error(t, err)
		})
	}
}

// The v2 form must be exactly the certificate the CA's v2 form would have signed, so peers that only speak v2
// accept it. Ed25519 signatures are deterministic, so the bytes can be compared outright.
func TestCertificateV3_V2FormIsExact(t *testing.T) {
	ca, caKey, host, _ := newTestV3(t, Curve_CURVE25519)
	classicalCAKey := caKey[:len(caKey)-MLDSA87PrivateKeySize]
	classicalPub := V2Form(host).PublicKey()

	tbs := &TBSCertificate{
		Version:   Version2,
		Curve:     Curve_CURVE25519,
		Name:      host.Name(),
		Networks:  host.Networks(),
		Groups:    host.Groups(),
		NotBefore: host.NotBefore(),
		NotAfter:  host.NotAfter(),
		PublicKey: classicalPub,
	}
	v2, err := tbs.Sign(V2Form(ca), Curve_CURVE25519, classicalCAKey)
	require.NoError(t, err)

	want, err := v2.Marshal()
	require.NoError(t, err)
	got, err := V2Form(host).Marshal()
	require.NoError(t, err)
	assert.Equal(t, want, got)

	wantHS, err := v2.MarshalForHandshakes()
	require.NoError(t, err)
	gotHS, err := V2Form(host).MarshalForHandshakes()
	require.NoError(t, err)
	assert.Equal(t, wantHS, gotHS)

	assert.Nil(t, V2Form(v2))
}

func TestCertificateV3_MarshalRoundTrip(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, _, host, _ := newTestV3(t, curve)

			for _, c := range []Certificate{ca, host} {
				b, err := c.Marshal()
				require.NoError(t, err)
				c2, err := unmarshalCertificateV3(b, nil, Curve_CURVE25519)
				require.NoError(t, err)
				assertCertsEqual(t, c, c2)

				p, err := c.MarshalPEM()
				require.NoError(t, err)
				c3, rest, err := UnmarshalCertificateFromPEM(p)
				require.NoError(t, err)
				assert.Empty(t, rest)
				assertCertsEqual(t, c, c3)

				// Handshakes carry the composite public key in the noise static, not in the certificate.
				hs, err := c.MarshalForHandshakes()
				require.NoError(t, err)
				assert.Less(t, len(hs), len(b)-len(c.PublicKey()))
				c4, err := Recombine(Version3, hs, c.PublicKey(), curve)
				require.NoError(t, err)
				assertCertsEqual(t, c, c4)

				_, err = Recombine(Version3, b, c.PublicKey(), curve)
				require.ErrorIs(t, err, ErrCertPubkeyPresent)
			}
		})
	}
}

func assertCertsEqual(t *testing.T, want, got Certificate) {
	t.Helper()
	wb, err := want.Marshal()
	require.NoError(t, err)
	gb, err := got.Marshal()
	require.NoError(t, err)
	assert.Equal(t, wb, gb)
	wf, err := want.Fingerprint()
	require.NoError(t, err)
	gf, err := got.Fingerprint()
	require.NoError(t, err)
	assert.Equal(t, wf, gf)
	assert.Equal(t, want.PublicKey(), got.PublicKey())
}

// rebuildV3 re-encodes a v3 certificate's envelope after edit has had a go at its fields.
func rebuildV3(t *testing.T, c Certificate, edit func(fields map[asn1.Tag][]byte, order *[]asn1.Tag)) []byte {
	t.Helper()
	b, err := c.Marshal()
	require.NoError(t, err)
	in := cryptobyte.String(b)
	var body cryptobyte.String
	require.True(t, in.ReadASN1(&body, asn1.SEQUENCE))

	fields := map[asn1.Tag][]byte{}
	var order []asn1.Tag
	for !body.Empty() {
		var el cryptobyte.String
		var tag asn1.Tag
		require.True(t, body.ReadAnyASN1Element(&el, &tag))
		fields[tag] = el
		order = append(order, tag)
	}
	edit(fields, &order)

	var out cryptobyte.Builder
	out.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, tag := range order {
			b.AddBytes(fields[tag])
		}
	})
	return out.BytesOrPanic()
}

func TestCertificateV3_StrictParse(t *testing.T) {
	_, _, host, _ := newTestV3(t, Curve_CURVE25519)
	good, err := host.Marshal()
	require.NoError(t, err)

	_, err = unmarshalCertificateV3(append(good, 0), nil, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrBadFormat, "trailing bytes after the envelope")

	trailing := rebuildV3(t, host, func(fields map[asn1.Tag][]byte, order *[]asn1.Tag) {
		fields[6|classContextSpecific] = []byte{6 | classContextSpecific, 1, 0}
		*order = append(*order, 6|classContextSpecific)
	})
	_, err = unmarshalCertificateV3(trailing, nil, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrBadFormat, "unknown field after the pq signature")

	for _, tag := range []asn1.Tag{TagCertPQPublicKey, TagCertPQSignature} {
		missing := rebuildV3(t, host, func(fields map[asn1.Tag][]byte, order *[]asn1.Tag) {
			*order = removeTag(*order, tag)
		})
		_, err = unmarshalCertificateV3(missing, nil, Curve_CURVE25519)
		require.Error(t, err, "missing %x", tag)
	}

	// A v2 certificate is not a v3 one.
	v2, err := V2Form(host).Marshal()
	require.NoError(t, err)
	_, err = unmarshalCertificateV3(v2, nil, Curve_CURVE25519)
	require.Error(t, err)

	// A wrong sized post-quantum key fails validation.
	short := rebuildV3(t, host, func(fields map[asn1.Tag][]byte, order *[]asn1.Tag) {
		var b cryptobyte.Builder
		b.AddASN1(TagCertPQPublicKey, func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, MLKEM1024PublicKeySize-1)) })
		fields[TagCertPQPublicKey] = b.BytesOrPanic()
	})
	_, err = unmarshalCertificateV3(short, nil, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
}

func removeTag(order []asn1.Tag, tag asn1.Tag) []asn1.Tag {
	var out []asn1.Tag
	for _, t := range order {
		if t != tag {
			out = append(out, t)
		}
	}
	return out
}

func TestCertificateV3_Tamper(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, _, host, _ := newTestV3(t, curve)

			// Swapping the post-quantum key breaks only the post-quantum signature, which must still catch it.
			dk, err := mlkem.GenerateKey1024()
			require.NoError(t, err)
			swapped := host.Copy().(*certificateV3)
			swapped.pqPublicKey = dk.EncapsulationKey().Bytes()
			assert.True(t, V2Form(swapped).CheckSignature(V2Form(ca).PublicKey()))
			assert.False(t, swapped.CheckSignature(ca.PublicKey()))

			// The post-quantum signature covers the classical one.
			resigned := host.Copy().(*certificateV3)
			if curve == Curve_P256 {
				sig, err := p256.Swap(resigned.v2.signature)
				require.NoError(t, err)
				resigned.v2.signature = sig
				assert.True(t, V2Form(resigned).CheckSignature(V2Form(ca).PublicKey()))
			} else {
				resigned.v2.signature[0] ^= 1
			}
			assert.False(t, resigned.CheckSignature(ca.PublicKey()))

			// Another CA's post-quantum key does not verify.
			other, _, _, _ := NewTestCaCert(Version3, curve, time.Time{}, time.Time{}, nil, nil, nil)
			k := append(V2Form(ca).PublicKey(), other.PublicKey()[len(V2Form(other).PublicKey()):]...)
			assert.False(t, host.CheckSignature(k))
		})
	}
}

func TestCAPool_V3(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, _, host, _ := newTestV3(t, curve)
			now := time.Now()

			// A v3 CA verifies v3 certificates, and only those.
			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			cc, err := pool.VerifyCertificate(now, host)
			require.NoError(t, err)
			require.NoError(t, pool.VerifyCachedCertificate(now, cc))
			_, err = pool.VerifyCertificate(now, V2Form(host))
			require.ErrorIs(t, err, ErrCaNotFound)

			// Listing the v2 form of the CA as well accepts the v2 form of the certificate.
			require.NoError(t, pool.AddCA(V2Form(ca)))
			_, err = pool.VerifyCertificate(now, V2Form(host))
			require.NoError(t, err)
			_, err = pool.VerifyCertificate(now, host)
			require.NoError(t, err)

			// The v2 form of the CA alone does not verify a v3 certificate.
			v2Pool := NewCAPool()
			require.NoError(t, v2Pool.AddCA(V2Form(ca)))
			_, err = v2Pool.VerifyCertificate(now, host)
			require.ErrorIs(t, err, ErrCaNotFound)

			// A second v3 extension of the same v2 CA is ambiguous.
			sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
			require.NoError(t, err)
			signPQ, err := SignPQ(sk.Bytes())
			require.NoError(t, err)
			again, err := ExtendToV3(V2Form(ca), sk.PublicKey().Bytes(), nil, signPQ)
			require.NoError(t, err)
			require.ErrorContains(t, pool.AddCA(again), "two version 3 CAs extend the same version 2 CA")
		})
	}
}

func TestCAPool_V3Blocklist(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, _, host, _ := newTestV3(t, curve)
			now := time.Now()
			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			require.NoError(t, pool.AddCA(V2Form(ca)))
			cc, err := pool.VerifyCertificate(now, host)
			require.NoError(t, err)

			fp, err := host.Fingerprint()
			require.NoError(t, err)
			v2Fp, err := V2Form(host).Fingerprint()
			require.NoError(t, err)
			assert.NotEqual(t, fp, v2Fp)

			// Blocking the v3 fingerprint leaves the v2 form alone, which is why operators list both.
			pool.BlocklistFingerprint(fp)
			_, err = pool.VerifyCertificate(now, host)
			require.ErrorIs(t, err, ErrBlockListed)
			require.ErrorIs(t, pool.VerifyCachedCertificate(now, cc), ErrBlockListed)
			_, err = pool.VerifyCertificate(now, V2Form(host))
			require.NoError(t, err)

			// Blocking the v2 fingerprint blocks both.
			pool.ResetCertBlocklist()
			pool.BlocklistFingerprint(v2Fp)
			_, err = pool.VerifyCertificate(now, host)
			require.ErrorIs(t, err, ErrBlockListed)
			require.ErrorIs(t, pool.VerifyCachedCertificate(now, cc), ErrBlockListed)
			_, err = pool.VerifyCertificate(now, V2Form(host))
			require.ErrorIs(t, err, ErrBlockListed)

			if curve == Curve_P256 {
				// So does the other form of a P256 v2 signature.
				alt, err := CalculateAlternateFingerprint(V2Form(host))
				require.NoError(t, err)
				pool.ResetCertBlocklist()
				pool.BlocklistFingerprint(alt)
				_, err = pool.VerifyCertificate(now, host)
				require.ErrorIs(t, err, ErrBlockListed)
			}
		})
	}
}

// Certificates already in use extend in place: their v2 forms, and fingerprints, do not change.
func TestExtendToV3(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca2, _, caKey2, _ := NewTestCaCert(Version2, curve, time.Time{}, time.Time{}, nil, nil, nil)
			host2, _, _, _ := NewTestCert(Version2, curve, ca2, caKey2, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)

			sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
			require.NoError(t, err)
			signPQ, err := SignPQ(sk.Bytes())
			require.NoError(t, err)

			ca3, err := ExtendToV3(ca2, sk.PublicKey().Bytes(), nil, signPQ)
			require.NoError(t, err)
			assertCertsEqual(t, ca2, V2Form(ca3))
			require.NoError(t, ca3.VerifyPrivateKey(curve, append(caKey2, sk.Bytes()...)))

			dk, err := mlkem.GenerateKey1024()
			require.NoError(t, err)
			host3, err := ExtendToV3(host2, dk.EncapsulationKey().Bytes(), ca3, signPQ)
			require.NoError(t, err)
			assertCertsEqual(t, host2, V2Form(host3))

			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca3))
			_, err = pool.VerifyCertificate(time.Now(), host3)
			require.NoError(t, err)

			// A host must be extended by its own issuer, and with that issuer's key.
			other2, _, _, _ := NewTestCaCert(Version2, curve, time.Time{}, time.Time{}, nil, nil, nil)
			other3, err := ExtendToV3(other2, sk.PublicKey().Bytes(), nil, signPQ)
			require.NoError(t, err)
			_, err = ExtendToV3(host2, dk.EncapsulationKey().Bytes(), other3, signPQ)
			require.Error(t, err)

			wrong, err := mldsa.GenerateKey(mldsa.MLDSA87())
			require.NoError(t, err)
			wrongSign, err := SignPQ(wrong.Bytes())
			require.NoError(t, err)
			_, err = ExtendToV3(host2, dk.EncapsulationKey().Bytes(), ca3, wrongSign)
			require.ErrorIs(t, err, ErrSignatureMismatch)

			// A CA extends itself, and needs its own post-quantum key to.
			_, err = ExtendToV3(ca2, sk.PublicKey().Bytes(), nil, wrongSign)
			require.ErrorIs(t, err, ErrSignatureMismatch)
			_, err = ExtendToV3(ca2, sk.PublicKey().Bytes(), ca3, signPQ)
			require.Error(t, err)

			// Only v2 certificates extend.
			_, err = ExtendToV3(host3, dk.EncapsulationKey().Bytes(), ca3, signPQ)
			require.Error(t, err)
		})
	}
}

func TestCertificateV3_KeyPEM(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host, hostKey := newTestV3(t, curve)

			pub, rest, gotCurve, err := UnmarshalPublicKeyFromPEM(host.MarshalPublicKeyPEM())
			require.NoError(t, err)
			assert.Empty(t, rest)
			assert.Equal(t, curve, gotCurve)
			assert.Equal(t, host.PublicKey(), pub)

			pub, _, gotCurve, err = UnmarshalSigningPublicKeyFromPEM(ca.MarshalPublicKeyPEM())
			require.NoError(t, err)
			assert.Equal(t, curve, gotCurve)
			assert.Equal(t, ca.PublicKey(), pub)

			key, _, gotCurve, err := UnmarshalPrivateKeyFromPEM(MarshalPrivateKeyToPEM(curve, hostKey))
			require.NoError(t, err)
			assert.Equal(t, curve, gotCurve)
			assert.Equal(t, hostKey, key)

			key, _, gotCurve, err = UnmarshalSigningPrivateKeyFromPEM(MarshalSigningPrivateKeyToPEM(curve, caKey))
			require.NoError(t, err)
			assert.Equal(t, curve, gotCurve)
			assert.Equal(t, caKey, key)

			kdf := NewArgon2Parameters(64*1024, 4, 1)
			enc, err := EncryptAndMarshalSigningPrivateKey(curve, caKey, []byte("pw"), kdf)
			require.NoError(t, err)
			_, _, _, err = UnmarshalSigningPrivateKeyFromPEM(enc)
			require.ErrorIs(t, err, ErrPrivateKeyEncrypted)
			gotCurve, key, _, err = DecryptAndUnmarshalSigningPrivateKey([]byte("pw"), enc)
			require.NoError(t, err)
			assert.Equal(t, curve, gotCurve)
			assert.Equal(t, caKey, key)
		})
	}
}
