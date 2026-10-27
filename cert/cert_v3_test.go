package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
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
	skipWithoutPQ(t)
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

			// The issuer is the v3 CA itself, and the v2 form's issuer is the CA's v2 form, which old peers know it by.
			caFp, err := ca.Fingerprint()
			require.NoError(t, err)
			caV2Fp, err := V2Form(ca).Fingerprint()
			require.NoError(t, err)
			assert.Equal(t, caFp, host.Issuer())
			assert.Equal(t, caV2Fp, V2Form(host).Issuer())
			assert.Empty(t, ca.Issuer())

			// A v2 CA can not sign a v3 certificate, nor a v3 CA a v2 one.
			_, err = (&TBSCertificate{Version: Version3, Curve: curve, PQSuite: DefaultPQSuite, Name: "x", Networks: host.Networks(), NotBefore: host.NotBefore(), NotAfter: host.NotAfter(), PublicKey: host.PublicKey()}).Sign(V2Form(ca), curve, caKey)
			require.Error(t, err)
		})
	}
}

// The v2 form must be exactly the certificate the CA's v2 form would have signed, so peers that only speak v2
// accept it. Ed25519 signatures are deterministic, so the bytes can be compared outright.
func TestCertificateV3_V2FormIsExact(t *testing.T) {
	skipWithoutPQ(t)
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
	skipWithoutPQ(t)
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
	skipWithoutPQ(t)
	_, _, host, _ := newTestV3(t, Curve_CURVE25519)
	good, err := host.Marshal()
	require.NoError(t, err)

	_, err = unmarshalCertificateV3(append(good, 0), nil, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrBadFormat, "trailing bytes after the envelope")

	trailing := rebuildV3(t, host, func(fields map[asn1.Tag][]byte, order *[]asn1.Tag) {
		fields[9|classContextSpecific] = []byte{9 | classContextSpecific, 1, 0}
		*order = append(*order, 9|classContextSpecific)
	})
	_, err = unmarshalCertificateV3(trailing, nil, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrBadFormat, "unknown field after the pq signature")

	// There is no extensions field: an element where one used to go is refused.
	withExt := rebuildV3(t, host, func(fields map[asn1.Tag][]byte, order *[]asn1.Tag) {
		const ext = asn1.Tag(9 | classConstructed | classContextSpecific)
		fields[ext] = []byte{byte(ext), 2, 3 | classContextSpecific, 0}
		var o []asn1.Tag
		for _, tag := range *order {
			if tag == TagCertClassicalSignature {
				o = append(o, ext)
			}
			o = append(o, tag)
		}
		*order = o
	})
	_, err = unmarshalCertificateV3(withExt, nil, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrBadFormat, "a field before the signatures")

	for _, tag := range []asn1.Tag{TagCertPQSuite, TagCertPQIssuer, TagCertPQPublicKey, TagCertClassicalSignature, TagCertPQSignature} {
		missing := rebuildV3(t, host, func(fields map[asn1.Tag][]byte, order *[]asn1.Tag) {
			*order = removeTag(*order, tag)
		})
		_, err = unmarshalCertificateV3(missing, nil, Curve_CURVE25519)
		require.Error(t, err, "missing %x", tag)
	}

	// The issuer is a fingerprint.
	for _, issuer := range [][]byte{{}, make([]byte, 31), make([]byte, 33)} {
		bad := rebuildV3(t, host, func(fields map[asn1.Tag][]byte, order *[]asn1.Tag) {
			var b cryptobyte.Builder
			b.AddASN1(TagCertPQIssuer, func(b *cryptobyte.Builder) { b.AddBytes(issuer) })
			fields[TagCertPQIssuer] = b.BytesOrPanic()
		})
		_, err = unmarshalCertificateV3(bad, nil, Curve_CURVE25519)
		require.ErrorIs(t, err, ErrBadFormat, "issuer of %d bytes", len(issuer))
	}

	// A CA signs itself, so it names no issuer.
	ca, _, _, _ := newTestV3(t, Curve_CURVE25519)
	caIssued := rebuildV3(t, ca, func(fields map[asn1.Tag][]byte, order *[]asn1.Tag) {
		var b cryptobyte.Builder
		b.AddASN1(TagCertPQIssuer, func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 32)) })
		fields[TagCertPQIssuer] = b.BytesOrPanic()
		var o []asn1.Tag
		for _, tag := range *order {
			o = append(o, tag)
			if tag == TagCertPQSuite {
				o = append(o, TagCertPQIssuer)
			}
		}
		*order = o
	})
	_, err = unmarshalCertificateV3(caIssued, nil, Curve_CURVE25519)
	require.ErrorIs(t, err, ErrBadFormat, "a CA with an issuer")

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

	// The suite is one first value, PQSuiteUnknown included in what is not.
	for _, suite := range [][]byte{{byte(PQSuiteUnknown)}, {200}, {}, {1, 1}} {
		bad := rebuildV3(t, host, func(fields map[asn1.Tag][]byte, order *[]asn1.Tag) {
			var b cryptobyte.Builder
			b.AddASN1(TagCertPQSuite, func(b *cryptobyte.Builder) { b.AddBytes(suite) })
			fields[TagCertPQSuite] = b.BytesOrPanic()
		})
		_, err = unmarshalCertificateV3(bad, nil, Curve_CURVE25519)
		require.Error(t, err, "suite %x", suite)
	}
}

// signers returns the two signers of a v3 certificate of curve, from the halves of a composite CA key.
func signers(t *testing.T, curve Curve, classicalKey, seed []byte) (sign, signPQ SignerLambda) {
	t.Helper()
	sign, err := SignClassical(curve, classicalKey)
	require.NoError(t, err)
	signPQ, err = SignPQ(DefaultPQSuite, curve, seed)
	require.NoError(t, err)
	return sign, signPQ
}

// compositeSigners returns the two signers of a composite CA key.
func compositeSigners(t *testing.T, curve Curve, caKey []byte) (sign, signPQ SignerLambda) {
	t.Helper()
	classicalKey, seed, err := DefaultPQSuite.SplitPrivateKey(true, caKey)
	require.NoError(t, err)
	return signers(t, curve, classicalKey, seed)
}

// resign signs both signatures of the whole certificate again, after a test changed a field.
func resign(t *testing.T, c3 *certificateV3, sign, signPQ SignerLambda) {
	t.Helper()
	m, err := c3.messagePrime()
	require.NoError(t, err)
	c3.classicalSignature, err = sign(m)
	require.NoError(t, err)
	if c3.v2.curve == Curve_P256 {
		c3.classicalSignature, err = p256.Normalize(c3.classicalSignature)
		require.NoError(t, err)
	}
	c3.pqSignature, err = signPQ(m)
	require.NoError(t, err)
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
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host, _ := newTestV3(t, curve)

			// Swapping the post-quantum key leaves the v2 form intact, but both signatures of the whole certificate
			// catch it, each on its own.
			dk, err := mlkem.GenerateKey1024()
			require.NoError(t, err)
			swapped := host.Copy().(*certificateV3)
			swapped.pqPublicKey = dk.EncapsulationKey().Bytes()
			assert.True(t, V2Form(swapped).CheckSignature(V2Form(ca).PublicKey()))
			assert.False(t, swapped.CheckSignature(ca.PublicKey()))
			m, err := swapped.messagePrime()
			require.NoError(t, err)
			classicalCA, pqCA, err := DefaultPQSuite.SplitPublicKey(true, ca.PublicKey())
			require.NoError(t, err)
			assert.False(t, verifyClassical(curve, classicalCA, m, swapped.classicalSignature))
			assert.False(t, pqSuites[DefaultPQSuite].dsa.verify(pqCA, m, swapped.pqSignature, DefaultPQSuite.SignatureLabel(curve)))

			// Either signature of the whole certificate alone is not enough: the swap signed by the CA verifies, but
			// not with either of its signatures left as they were.
			sign, signPQ := compositeSigners(t, curve, caKey)
			signed := swapped.Copy().(*certificateV3)
			resign(t, signed, sign, signPQ)
			require.True(t, signed.CheckSignature(ca.PublicKey()))
			onlyPQ := signed.Copy().(*certificateV3)
			onlyPQ.classicalSignature = swapped.classicalSignature
			assert.False(t, onlyPQ.CheckSignature(ca.PublicKey()))
			onlyClassical := signed.Copy().(*certificateV3)
			onlyClassical.pqSignature = swapped.pqSignature
			assert.False(t, onlyClassical.CheckSignature(ca.PublicKey()))

			// Both signatures of the whole certificate cover the v2 form's signature.
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

// Both signatures of the whole certificate sign M' of draft-ietf-lamps-pq-composite-sigs, under nebula's own label.
func TestCertificateV3_SignedMessage(t *testing.T) {
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, _, host, _ := newTestV3(t, curve)
			c := host.(*certificateV3)
			label := map[Curve]string{
				Curve_CURVE25519: "NEBULA-CERTV3-MLDSA87-Ed25519-SHA512",
				Curve_P256:       "NEBULA-CERTV3-MLDSA87-ECDSA-P256-SHA512",
			}[curve]
			assert.Equal(t, label, DefaultPQSuite.SignatureLabel(curve))

			tbs, err := c.marshal(true, true)
			require.NoError(t, err)
			sum := sha512.Sum512(tbs)
			want := []byte("CompositeAlgorithmSignatures2025" + label)
			want = append(want, 21)
			want = append(want, "nebula certificate v3"...)
			want = append(want, sum[:]...)
			got, err := c.messagePrime()
			require.NoError(t, err)
			assert.Equal(t, want, got)

			// M is every field but the two signatures of the whole certificate, the v2 form's included.
			full, err := c.Marshal()
			require.NoError(t, err)
			assert.NotEqual(t, full, tbs)
			assert.True(t, bytes.Contains(tbs, c.v2.signature))
			assert.False(t, bytes.Contains(tbs, c.pqSignature))

			// The signatures Signature returns are those of the whole certificate, the v2 form has its own.
			sigs := host.Signature()
			assert.Equal(t, c.classicalSignature, sigs.Classical)
			assert.Equal(t, c.pqSignature, sigs.PQ)
			assert.Equal(t, c.v2.signature, V2Form(host).Signature().Classical)
			assert.Nil(t, V2Form(host).Signature().PQ)
			assert.NotEqual(t, sigs.Classical, V2Form(host).Signature().Classical)

			// The classical CA key's signature of the whole certificate verifies for M' and nothing shorter.
			classicalCA, _, err := DefaultPQSuite.SplitPublicKey(true, ca.PublicKey())
			require.NoError(t, err)
			assert.True(t, verifyClassical(curve, classicalCA, got, sigs.Classical))
			assert.False(t, verifyClassical(curve, classicalCA, tbs, sigs.Classical))
		})
	}
}

// cert_v3.asn1 defines the constants of the composite signature by value, and they must be the ones signing uses.
func TestCertificateV3_ASN1Constants(t *testing.T) {
	b, err := os.ReadFile("cert_v3.asn1")
	require.NoError(t, err)
	values := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^(\S+) VisibleString ::= "([^"]*)"`).FindAllStringSubmatch(string(b), -1) {
		values[m[1]] = m[2]
	}
	assert.Equal(t, map[string]string{
		"compositeSignaturePrefix": compositeSignaturePrefix,
		"signatureContext":         signatureContext,
		"labelMLDSA87-Ed25519":     DefaultPQSuite.SignatureLabel(Curve_CURVE25519),
		"labelMLDSA87-ECDSA-P256":  DefaultPQSuite.SignatureLabel(Curve_P256),
	}, values)
}

// The classical signature of a P256 certificate must be low-s: the high-s form also verifies, and nothing else covers
// it, so it would give the certificate a second encoding and fingerprint.
func TestCertificateV3_P256LowS(t *testing.T) {
	skipWithoutPQ(t)
	ca, _, host, _ := newTestV3(t, Curve_P256)
	high := host.Copy().(*certificateV3)
	var err error
	high.classicalSignature, err = p256.Swap(high.classicalSignature)
	require.NoError(t, err)
	assert.False(t, high.CheckSignature(ca.PublicKey()))

	b, err := high.Marshal()
	require.NoError(t, err)
	_, err = unmarshalCertificateV3(b, nil, Curve_P256)
	require.ErrorIs(t, err, ErrBadFormat)

	alt, err := CalculateAlternateFingerprint(host)
	require.NoError(t, err)
	assert.Empty(t, alt)
}

func TestCAPool_V3(t *testing.T) {
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host, _ := newTestV3(t, curve)
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

			// A v3 certificate is bound to the v3 CA that issued it, not to the v2 CA that CA extends. A second
			// extension of the same v2 CA, with another post-quantum key, is a different CA.
			sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
			require.NoError(t, err)
			classicalKey, _, err := DefaultPQSuite.SplitPrivateKey(true, caKey)
			require.NoError(t, err)
			sign, signPQ := signers(t, curve, classicalKey, sk.Bytes())
			again, err := ExtendToV3(V2Form(ca), DefaultPQSuite, sk.PublicKey().Bytes(), nil, sign, signPQ)
			require.NoError(t, err)
			againHost, err := ExtendToV3(V2Form(host), DefaultPQSuite, host.PublicKey()[len(V2Form(host).PublicKey()):], again, sign, signPQ)
			require.NoError(t, err)

			againPool := NewCAPool()
			require.NoError(t, againPool.AddCA(again))
			_, err = againPool.VerifyCertificate(now, againHost)
			require.NoError(t, err)
			_, err = againPool.VerifyCertificate(now, host)
			require.ErrorIs(t, err, ErrCaNotFound)

			// Both extensions can be trusted at once, each verifying what it issued.
			require.NoError(t, pool.AddCA(again))
			for _, c := range []Certificate{host, againHost} {
				cc, err := pool.VerifyCertificate(now, c)
				require.NoError(t, err)
				assert.Equal(t, c.Issuer(), cc.signerFingerprint)
			}
		})
	}
}

// Both forms of a v3 certificate must name the same CA. A CA reissued with the same keys is a different v2 CA, and a
// v3 certificate signed by its extension whose v2 form names the original is refused.
func TestCAPool_V3IssuerForms(t *testing.T) {
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host, _ := newTestV3(t, curve)
			classicalKey, pqSeed, err := DefaultPQSuite.SplitPrivateKey(true, caKey)
			require.NoError(t, err)
			classicalPub, pqPub, err := DefaultPQSuite.SplitPublicKey(true, ca.PublicKey())
			require.NoError(t, err)
			sign, signPQ := signers(t, curve, classicalKey, pqSeed)

			reissuedV2, err := (&TBSCertificate{
				Version: Version2, Curve: curve, IsCA: true, Name: ca.Name(), Groups: ca.Groups(),
				NotBefore: ca.NotBefore(), NotAfter: ca.NotAfter().Add(time.Second), PublicKey: classicalPub,
			}).Sign(nil, curve, classicalKey)
			require.NoError(t, err)
			reissued, err := ExtendToV3(reissuedV2, DefaultPQSuite, pqPub, nil, sign, signPQ)
			require.NoError(t, err)

			forged := host.Copy().(*certificateV3)
			forged.issuer, err = reissued.Fingerprint()
			require.NoError(t, err)
			resign(t, forged, sign, signPQ)
			require.True(t, forged.CheckSignature(reissued.PublicKey()), "every signature verifies")

			pool := NewCAPool()
			require.NoError(t, pool.AddCA(reissued))
			_, err = pool.VerifyCertificate(time.Now(), forged)
			require.ErrorIs(t, err, ErrFingerprintMismatch)
		})
	}
}

func TestCAPool_V3Blocklist(t *testing.T) {
	skipWithoutPQ(t)
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
			assert.Equal(t, v2Fp, cc.V2Fingerprint())
			cc2, err := pool.VerifyCertificate(now, V2Form(host))
			require.NoError(t, err)
			assert.Empty(t, cc2.V2Fingerprint())

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
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca2, _, caKey2, _ := NewTestCaCert(Version2, curve, time.Time{}, time.Time{}, nil, nil, nil)
			host2, _, _, _ := NewTestCert(Version2, curve, ca2, caKey2, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)

			sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
			require.NoError(t, err)
			sign, signPQ := signers(t, curve, caKey2, sk.Bytes())

			ca3, err := ExtendToV3(ca2, DefaultPQSuite, sk.PublicKey().Bytes(), nil, sign, signPQ)
			require.NoError(t, err)
			assertCertsEqual(t, ca2, V2Form(ca3))
			require.NoError(t, ca3.VerifyPrivateKey(curve, append(caKey2, sk.Bytes()...)))

			dk, err := mlkem.GenerateKey1024()
			require.NoError(t, err)
			host3, err := ExtendToV3(host2, DefaultPQSuite, dk.EncapsulationKey().Bytes(), ca3, sign, signPQ)
			require.NoError(t, err)
			assertCertsEqual(t, host2, V2Form(host3))

			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca3))
			_, err = pool.VerifyCertificate(time.Now(), host3)
			require.NoError(t, err)

			// A host must be extended by its own issuer, and with that issuer's key.
			other2, _, otherKey2, _ := NewTestCaCert(Version2, curve, time.Time{}, time.Time{}, nil, nil, nil)
			otherSign, _ := signers(t, curve, otherKey2, sk.Bytes())
			other3, err := ExtendToV3(other2, DefaultPQSuite, sk.PublicKey().Bytes(), nil, otherSign, signPQ)
			require.NoError(t, err)
			_, err = ExtendToV3(host2, DefaultPQSuite, dk.EncapsulationKey().Bytes(), other3, otherSign, signPQ)
			require.Error(t, err)

			wrong, err := mldsa.GenerateKey(mldsa.MLDSA87())
			require.NoError(t, err)
			_, wrongSignPQ := signers(t, curve, caKey2, wrong.Bytes())
			_, err = ExtendToV3(host2, DefaultPQSuite, dk.EncapsulationKey().Bytes(), ca3, sign, wrongSignPQ)
			require.ErrorIs(t, err, ErrSignatureMismatch)
			_, err = ExtendToV3(host2, DefaultPQSuite, dk.EncapsulationKey().Bytes(), ca3, otherSign, signPQ)
			require.ErrorIs(t, err, ErrSignatureMismatch)

			// A CA extends itself, and needs both of its own keys to. Its public v2 certificate and a post-quantum key
			// of one's own are not enough.
			_, err = ExtendToV3(ca2, DefaultPQSuite, sk.PublicKey().Bytes(), nil, sign, wrongSignPQ)
			require.ErrorIs(t, err, ErrSignatureMismatch)
			_, err = ExtendToV3(ca2, DefaultPQSuite, sk.PublicKey().Bytes(), nil, otherSign, signPQ)
			require.ErrorIs(t, err, ErrSignatureMismatch)
			_, err = ExtendToV3(ca2, DefaultPQSuite, sk.PublicKey().Bytes(), ca3, sign, signPQ)
			require.Error(t, err)

			// Only v2 certificates extend.
			_, err = ExtendToV3(host3, DefaultPQSuite, dk.EncapsulationKey().Bytes(), ca3, sign, signPQ)
			require.Error(t, err)
		})
	}
}

// Every signature of an extension is deterministic, ML-DSA-87, Ed25519 and RFC 6979 ECDSA P256, so extending a
// certificate twice gives the same bytes and the same fingerprint: pq-extend is idempotent, and a CA extended again is
// not a second v3 CA to the pool.
func TestExtendToV3_Deterministic(t *testing.T) {
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca2, _, caKey2, _ := NewTestCaCert(Version2, curve, time.Time{}, time.Time{}, nil, nil, nil)
			host2, _, _, _ := NewTestCert(Version2, curve, ca2, caKey2, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)
			sk, err := mldsa.GenerateKey(mldsa.MLDSA87())
			require.NoError(t, err)
			sign, signPQ := signers(t, curve, caKey2, sk.Bytes())
			dk, err := mlkem.GenerateKey1024()
			require.NoError(t, err)

			extend := func(c Certificate, pq []byte, signer Certificate) ([]byte, string, Certificate) {
				c3, err := ExtendToV3(c, DefaultPQSuite, pq, signer, sign, signPQ)
				require.NoError(t, err)
				b, err := c3.Marshal()
				require.NoError(t, err)
				fp, err := c3.Fingerprint()
				require.NoError(t, err)
				return b, fp, c3
			}

			caBytesA, caFpA, caA := extend(ca2, sk.PublicKey().Bytes(), nil)
			caBytesB, caFpB, caB := extend(ca2, sk.PublicKey().Bytes(), nil)
			assert.Equal(t, caBytesA, caBytesB)
			assert.Equal(t, caFpA, caFpB)

			hostBytesA, hostFpA, _ := extend(host2, dk.EncapsulationKey().Bytes(), caA)
			hostBytesB, hostFpB, _ := extend(host2, dk.EncapsulationKey().Bytes(), caB)
			assert.Equal(t, hostBytesA, hostBytesB)
			assert.Equal(t, hostFpA, hostFpB)

			pool := NewCAPool()
			require.NoError(t, pool.AddCA(caA))
			require.NoError(t, pool.AddCA(caB))
		})
	}
}

func TestCertificateV3_KeyPEM(t *testing.T) {
	skipWithoutPQ(t)
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

			key, _, gotCurve, err := UnmarshalPrivateKeyFromPEM(MarshalPQPrivateKeyToPEM(curve, DefaultPQSuite, hostKey))
			require.NoError(t, err)
			assert.Equal(t, curve, gotCurve)
			assert.Equal(t, hostKey, key)

			key, _, gotCurve, err = UnmarshalSigningPrivateKeyFromPEM(MarshalPQSigningPrivateKeyToPEM(curve, DefaultPQSuite, caKey))
			require.NoError(t, err)
			assert.Equal(t, curve, gotCurve)
			assert.Equal(t, caKey, key)

			kdf := NewArgon2Parameters(64*1024, 4, 1)
			enc, err := EncryptAndMarshalPQSigningPrivateKey(curve, DefaultPQSuite, caKey, []byte("pw"), kdf)
			require.NoError(t, err)
			_, _, _, err = UnmarshalSigningPrivateKeyFromPEM(enc)
			require.ErrorIs(t, err, ErrPrivateKeyEncrypted)
			gotCurve, key, _, err = DecryptAndUnmarshalSigningPrivateKey([]byte("pw"), enc)
			require.NoError(t, err)
			assert.Equal(t, curve, gotCurve)
			assert.Equal(t, caKey, key)

			// The banners name both halves.
			assert.Contains(t, string(MarshalPQPrivateKeyToPEM(curve, DefaultPQSuite, hostKey)), " MLKEM1024 PRIVATE KEY-----")
			assert.Contains(t, string(MarshalPQSigningPrivateKeyToPEM(curve, DefaultPQSuite, caKey)), " MLDSA87 PRIVATE KEY-----")
			assert.Contains(t, string(enc), " MLDSA87 ENCRYPTED PRIVATE KEY-----")

			// A key of the wrong size, or for an unknown suite, has no banner.
			assert.Nil(t, MarshalPQPrivateKeyToPEM(curve, DefaultPQSuite, hostKey[1:]))
			assert.Nil(t, MarshalPQPrivateKeyToPEM(curve, PQSuiteUnknown, hostKey))
			assert.Nil(t, MarshalPQSigningPrivateKeyToPEM(curve, DefaultPQSuite, caKey[1:]))
			_, err = EncryptAndMarshalPQSigningPrivateKey(curve, DefaultPQSuite, caKey[1:], []byte("pw"), kdf)
			require.Error(t, err)
		})
	}
}

// newTestV3WithoutV2Form issues a v3 CA and a host certificate without v2 forms.
func newTestV3WithoutV2Form(t *testing.T, curve Curve) (ca Certificate, caKey []byte, host Certificate) {
	t.Helper()
	var pub, priv []byte
	if curve == Curve_P256 {
		privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub = elliptic.Marshal(elliptic.P256(), privk.PublicKey.X, privk.PublicKey.Y)
		priv = privk.D.FillBytes(make([]byte, 32))
	} else {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
	}
	pub, priv = appendPQSigningKey(pub, priv)
	now := time.Now()
	ca, err := (&TBSCertificate{
		Version: Version3, Curve: curve, PQSuite: DefaultPQSuite, OmitV2Form: true, IsCA: true, Name: "pure ca",
		Groups: []string{"g"}, NotBefore: time.Unix(now.Add(-time.Minute).Unix(), 0), NotAfter: time.Unix(now.Add(time.Hour).Unix(), 0),
		PublicKey: pub,
	}).Sign(nil, curve, priv)
	require.NoError(t, err)
	host, _, _, _ = NewTestCert(Version3, curve, ca, priv, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, []string{"g"})
	return ca, priv, host
}

// topLevelTags returns the tags of a certificate's top level fields.
func topLevelTags(t *testing.T, c Certificate) []asn1.Tag {
	t.Helper()
	var tags []asn1.Tag
	rebuildV3(t, c, func(_ map[asn1.Tag][]byte, order *[]asn1.Tag) { tags = slices.Clone(*order) })
	return tags
}

// A v3 certificate without a v2 form carries no v2 signature and its details name no issuer. It is for v3 peers
// only, and smaller for it.
func TestCertificateV3_WithoutV2Form(t *testing.T) {
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host := newTestV3WithoutV2Form(t, curve)
			assert.Nil(t, V2Form(ca))
			assert.Nil(t, V2Form(host))
			caFp, err := ca.Fingerprint()
			require.NoError(t, err)
			assert.Equal(t, caFp, host.Issuer())
			assert.Empty(t, host.(*certificateV3).v2.details.issuer)
			for _, c := range []Certificate{ca, host} {
				assert.NotContains(t, topLevelTags(t, c), asn1.Tag(TagCertSignature))
			}

			// It round trips, whole and through a handshake.
			b, err := host.Marshal()
			require.NoError(t, err)
			parsed, err := unmarshalCertificateV3(b, nil, Curve_CURVE25519)
			require.NoError(t, err)
			assertCertsEqual(t, host, parsed)
			hs, err := host.MarshalForHandshakes()
			require.NoError(t, err)
			recombined, err := Recombine(Version3, hs, host.PublicKey(), curve)
			require.NoError(t, err)
			assertCertsEqual(t, host, recombined)

			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			cc, err := pool.VerifyCertificate(time.Now(), recombined)
			require.NoError(t, err)
			assert.Empty(t, cc.V2Fingerprint())

			// No v2 keys in its JSON.
			j, err := host.MarshalJSON()
			require.NoError(t, err)
			var fields map[string]any
			require.NoError(t, json.Unmarshal(j, &fields))
			for _, k := range []string{"v2Fingerprint", "v2Issuer", "v2Signature"} {
				assert.NotContains(t, fields, k)
			}
			assert.Equal(t, caFp, fields["issuer"])

			// A CA without a v2 form can not sign certificates with one, by signing or by extending.
			tbs := &TBSCertificate{
				Version: Version3, Curve: curve, PQSuite: DefaultPQSuite, Name: "x", Networks: host.Networks(),
				NotBefore: host.NotBefore(), NotAfter: host.NotAfter(), PublicKey: host.PublicKey(),
			}
			_, err = tbs.Sign(ca, curve, caKey)
			require.ErrorIs(t, err, ErrNoV2FormCA)
			v2CA, _, v2CAKey, _ := NewTestCaCert(Version2, curve, time.Time{}, time.Time{}, nil, nil, nil)
			v2Host, _, _, _ := NewTestCert(Version2, curve, v2CA, v2CAKey, "host", time.Time{}, time.Time{}, []netip.Prefix{netip.MustParsePrefix("10.1.0.1/16")}, nil, nil)
			sign, signPQ := compositeSigners(t, curve, caKey)
			_, err = ExtendToV3(v2Host, DefaultPQSuite, host.PublicKey()[len(host.(*certificateV3).v2.publicKey):], ca, sign, signPQ)
			require.ErrorIs(t, err, ErrNoV2FormCA)
		})
	}
}

// Dropping a v2 form is the CA's choice alone: both signatures of the whole certificate cover it.
func TestCertificateV3_V2FormCanNotBeStripped(t *testing.T) {
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host, _ := newTestV3(t, curve)

			// Without its signature, the details still name the v2 issuer, which is malformed.
			noSig := rebuildV3(t, host, func(_ map[asn1.Tag][]byte, order *[]asn1.Tag) {
				*order = removeTag(*order, TagCertSignature)
			})
			_, err := unmarshalCertificateV3(noSig, nil, Curve_CURVE25519)
			require.ErrorIs(t, err, ErrBadFormat)

			// Without the v2 issuer too it is well formed, but neither signature of the whole certificate verifies.
			stripped := host.Copy().(*certificateV3)
			stripped.v2.signature = nil
			stripped.v2.details.issuer = ""
			stripped.v2.rawDetails, err = stripped.v2.details.Marshal()
			require.NoError(t, err)
			require.NoError(t, stripped.validate())
			assert.Nil(t, V2Form(stripped))
			assert.False(t, stripped.CheckSignature(ca.PublicKey()))

			// The CA can issue a certificate without a v2 form, even when it has one itself.
			tbs := &TBSCertificate{
				Version: Version3, Curve: curve, PQSuite: DefaultPQSuite, OmitV2Form: true, Name: "pure", Networks: host.Networks(),
				Groups: host.Groups(), NotBefore: host.NotBefore(), NotAfter: host.NotAfter(), PublicKey: host.PublicKey(),
			}
			pure, err := tbs.Sign(ca, curve, caKey)
			require.NoError(t, err)
			assert.Nil(t, V2Form(pure))
			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			_, err = pool.VerifyCertificate(time.Now(), pure)
			require.NoError(t, err)

			// For Curve25519 the v2 form is the v2 signature and the v2 issuer, 100 bytes in every handshake.
			if curve == Curve_CURVE25519 {
				withForm, _, _, _ := NewTestCert(Version3, curve, ca, caKey, "pure", host.NotBefore(), host.NotAfter(), host.Networks(), nil, host.Groups())
				a, err := withForm.MarshalForHandshakes()
				require.NoError(t, err)
				b, err := pure.MarshalForHandshakes()
				require.NoError(t, err)
				assert.Equal(t, 2+ed25519.SignatureSize+2+sha256.Size, len(a)-len(b))
			}
		})
	}
}

// The pool refuses a certificate with a v2 form from a CA without one, even with every signature valid: there is no
// v2 CA the v2 form could name.
func TestCAPool_V2FormFromCAWithoutOne(t *testing.T) {
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, host := newTestV3WithoutV2Form(t, curve)
			classicalKey, _, err := DefaultPQSuite.SplitPrivateKey(true, caKey)
			require.NoError(t, err)
			classicalSign, err := classicalSigner(curve, classicalKey)
			require.NoError(t, err)

			forged := host.Copy().(*certificateV3)
			forged.v2.details.issuer = strings.Repeat("ab", sha256.Size)
			b, err := forged.v2.marshalForSigning()
			require.NoError(t, err)
			forged.v2.signature, err = classicalSign(b)
			require.NoError(t, err)
			if curve == Curve_P256 {
				forged.v2.signature, err = p256.Normalize(forged.v2.signature)
				require.NoError(t, err)
			}
			sign, signPQ := compositeSigners(t, curve, caKey)
			resign(t, forged, sign, signPQ)
			require.NoError(t, forged.validate())
			require.True(t, forged.CheckSignature(ca.PublicKey()))

			pool := NewCAPool()
			require.NoError(t, pool.AddCA(ca))
			_, err = pool.VerifyCertificate(time.Now(), forged)
			require.ErrorIs(t, err, ErrNoV2FormCA)
		})
	}
}

// A v2 certificate near the size limit grows past it when extended, so extending or signing it as v3 fails instead of
// making a certificate no parser accepts.
func TestCertificateV3_SizeLimit(t *testing.T) {
	skipWithoutPQ(t)
	ca, caKey, _, _ := newTestV3(t, Curve_CURVE25519)
	big := &TBSCertificate{Version: Version3, Curve: Curve_CURVE25519, PQSuite: DefaultPQSuite, Name: "big", Groups: []string{"g"}, NotBefore: ca.NotBefore(), NotAfter: ca.NotAfter()}
	// The CA limits groups to "g", so grow the certificate with networks instead, the ones its CA allows.
	for i := 0; ; i++ {
		big.Networks = append(big.Networks, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 32))
		if len(big.Networks)*7 > MaxCertificateSize-5000 {
			break
		}
	}
	pub, priv := X25519Keypair()
	big.PublicKey, _ = appendPQKey(ca, pub, priv)

	v2, err := (&TBSCertificate{Version: Version2, Curve: Curve_CURVE25519, Name: big.Name, Groups: big.Groups, Networks: big.Networks, NotBefore: big.NotBefore, NotAfter: big.NotAfter, PublicKey: pub}).Sign(V2Form(ca), Curve_CURVE25519, caKey[:len(caKey)-MLDSA87PrivateKeySize])
	require.NoError(t, err)
	b, err := v2.Marshal()
	require.NoError(t, err)
	require.Less(t, len(b), MaxCertificateSize, "the v2 certificate itself fits")

	sign, signPQ := compositeSigners(t, Curve_CURVE25519, caKey)
	_, err = ExtendToV3(v2, DefaultPQSuite, big.PublicKey[len(pub):], ca, sign, signPQ)
	require.ErrorIs(t, err, ErrBadFormat)
	_, err = big.Sign(ca, Curve_CURVE25519, caKey)
	require.ErrorIs(t, err, ErrBadFormat)
}

// A version 3 CA signs older certificates as its v2 form, by Sign with its composite key or by SignWith with its
// classical one: the issuer is the v2 form's, so the certificate verifies against it. A CA without a v2 form can not.
func TestSignOlderWithV3CA(t *testing.T) {
	skipWithoutPQ(t)
	for _, curve := range testCurves {
		t.Run(curve.String(), func(t *testing.T) {
			ca, caKey, _, _ := newTestV3(t, curve)
			pub, _ := X25519Keypair()
			if curve == Curve_P256 {
				pub, _ = P256Keypair()
			}
			tbs := func() *TBSCertificate {
				return &TBSCertificate{Version: Version2, Curve: curve, Name: "old", Groups: []string{"g"},
					Networks: []netip.Prefix{netip.MustParsePrefix("10.1.0.9/16")}, NotBefore: ca.NotBefore(), NotAfter: ca.NotAfter(), PublicKey: pub}
			}
			classicalKey, _, err := DefaultPQSuite.SplitPrivateKey(true, caKey)
			require.NoError(t, err)
			sp, err := classicalSigner(curve, classicalKey)
			require.NoError(t, err)

			viaSign, err := tbs().Sign(ca, curve, caKey)
			require.NoError(t, err)
			viaSignWith, err := tbs().SignWith(ca, curve, sp)
			require.NoError(t, err)

			v2Fp, err := V2Form(ca).Fingerprint()
			require.NoError(t, err)
			pool := NewCAPool()
			require.NoError(t, pool.AddCA(V2Form(ca)))
			for _, c := range []Certificate{viaSign, viaSignWith} {
				assert.Equal(t, v2Fp, c.Issuer())
				_, err = pool.VerifyCertificate(time.Now(), c)
				require.NoError(t, err)
			}

			pureCA, pureKey, _ := newTestV3WithoutV2Form(t, curve)
			_, err = tbs().Sign(pureCA, curve, pureKey)
			require.ErrorIs(t, err, ErrNoV2FormCA)
			_, err = tbs().SignWith(pureCA, curve, sp)
			require.ErrorIs(t, err, ErrNoV2FormCA)
		})
	}
}
