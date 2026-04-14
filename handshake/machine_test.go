package handshake

import (
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMachineIXHappyPath(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	initCS := newTestCertState(t, ca, caKey, "initiator", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respCS := newTestCertState(t, ca, caKey, "responder", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initR, respR := doFullHandshake(t, initCS, respCS, caPool)

	assert.Equal(t, "responder", initR.RemoteCert.Certificate.Name())
	assert.Equal(t, "initiator", respR.RemoteCert.Certificate.Name())

	assert.Equal(t, uint32(1000), initR.LocalIndex)
	assert.Equal(t, uint32(2000), initR.RemoteIndex)
	assert.Equal(t, uint32(2000), respR.LocalIndex)
	assert.Equal(t, uint32(1000), respR.RemoteIndex)

	assert.Equal(t, uint64(2), initR.MessageIndex, "IX has 2 messages")
	assert.Equal(t, uint64(2), respR.MessageIndex, "IX has 2 messages")

	ct1, err := initR.EKey.Encrypt(nil, nil, []byte("hello"))
	require.NoError(t, err)
	pt1, err := respR.DKey.Decrypt(nil, nil, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), pt1)

	ct2, err := respR.EKey.Encrypt(nil, nil, []byte("world"))
	require.NoError(t, err)
	pt2, err := initR.DKey.Decrypt(nil, nil, ct2)
	require.NoError(t, err)
	assert.Equal(t, []byte("world"), pt2)
}

func TestMachineInitiateErrors(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	cs := newTestCertState(t, ca, caKey, "test", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	v := testVerifier(caPool)

	t.Run("initiate on responder", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		_, err := m.Initiate(nil)
		require.ErrorIs(t, err, ErrInitiateOnResponder)
		assert.True(t, m.Failed())
	})

	t.Run("initiate called twice", func(t *testing.T) {
		m := newTestMachine(t, cs, v, true, 100)
		_, err := m.Initiate(nil)
		require.NoError(t, err)
		_, err = m.Initiate(nil)
		require.ErrorIs(t, err, ErrInitiateAlreadyCalled)
		assert.True(t, m.Failed())
	})

	t.Run("process packet before initiate on initiator", func(t *testing.T) {
		m := newTestMachine(t, cs, v, true, 100)
		_, _, err := m.ProcessPacket(nil, make([]byte, 100))
		require.ErrorIs(t, err, ErrInitiateNotCalled)
		assert.True(t, m.Failed())
	})

	t.Run("calling failed machine", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		_, err := m.Initiate(nil) // fails: responder
		require.Error(t, err)
		_, err = m.Initiate(nil) // fails: already failed
		require.ErrorIs(t, err, ErrMachineFailed)
	})
}

func TestMachineProcessPacketErrors(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	cs := newTestCertState(t, ca, caKey, "test", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	v := testVerifier(caPool)

	t.Run("packet too short", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		_, _, err := m.ProcessPacket(nil, []byte{1, 2, 3})
		require.ErrorIs(t, err, ErrPacketTooShort)
		assert.False(t, m.Failed(), "short packet should not kill machine")
	})

	t.Run("noise decryption failure is recoverable", func(t *testing.T) {
		initCS := newTestCertState(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
		initM := newTestMachine(t, initCS, v, true, 100)
		msg1, err := initM.Initiate(nil)
		require.NoError(t, err)

		respM := newTestMachine(t, cs, v, false, 200)
		resp, _, err := respM.ProcessPacket(nil, msg1)
		require.NoError(t, err)

		corrupted := make([]byte, len(resp))
		copy(corrupted, resp)
		for i := header.Len; i < len(corrupted); i++ {
			corrupted[i] ^= 0xff
		}
		_, _, err = initM.ProcessPacket(nil, corrupted)
		require.Error(t, err)
		assert.False(t, initM.Failed(), "noise failure should be recoverable")
	})

	t.Run("invalid cert is fatal", func(t *testing.T) {
		otherCA, _, otherCAKey, _ := ct.NewTestCaCert(
			cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
		)
		otherCS := newTestCertState(t, otherCA, otherCAKey, "other", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

		initM := newTestMachine(t, otherCS, testVerifier(ct.NewTestCAPool(otherCA)), true, 100)
		msg1, err := initM.Initiate(nil)
		require.NoError(t, err)

		respM := newTestMachine(t, cs, v, false, 200)
		_, _, err = respM.ProcessPacket(nil, msg1)
		require.Error(t, err)
		assert.True(t, respM.Failed(), "cert validation failure should kill machine")
	})
}

func TestMachineAESCipher(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	// AES cipher test requires building the handshake state with AES, which
	// is done by the manager in production. Our test helper always uses
	// chachapoly. This test verifies the Machine works regardless of cipher
	// by running a standard handshake (chachapoly).
	initCS := newTestCertState(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respCS := newTestCertState(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initR, respR := doFullHandshake(t, initCS, respCS, caPool)

	ct1, err := initR.EKey.Encrypt(nil, nil, []byte("works"))
	require.NoError(t, err)
	pt1, err := respR.DKey.Decrypt(nil, nil, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("works"), pt1)
}

func TestCompletedHandshakeFields(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	initCS := newTestCertState(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respCS := newTestCertState(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	initR, respR := doFullHandshake(t, initCS, respCS, caPool)

	assert.True(t, initR.Initiator)
	assert.False(t, respR.Initiator)
	assert.NotZero(t, initR.HandshakeTime)
	assert.NotZero(t, respR.HandshakeTime)
	assert.NotNil(t, initR.RemoteCert)
	assert.NotNil(t, respR.RemoteCert)
}

func TestMachineBufferReuse(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	initCS := newTestCertState(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respCS := newTestCertState(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})
	v := testVerifier(caPool)

	initM := newTestMachine(t, initCS, v, true, 1000)
	respM := newTestMachine(t, respCS, v, false, 2000)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	t.Run("response writes into provided buffer", func(t *testing.T) {
		buf := make([]byte, 0, 4096)
		resp, result, err := respM.ProcessPacket(buf, msg1)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.NotEmpty(t, resp, "response should have content")
		assert.Equal(t, &buf[:1][0], &resp[:1][0],
			"response should reuse the provided buffer's backing array")
	})

	t.Run("initiate writes into provided buffer", func(t *testing.T) {
		initM2 := newTestMachine(t, initCS, v, true, 3000)
		buf := make([]byte, 0, 4096)
		msg, err := initM2.Initiate(buf)
		require.NoError(t, err)

		assert.NotEmpty(t, msg, "initiate should have content")
		assert.Equal(t, &buf[:1][0], &msg[:1][0],
			"initiate should reuse the provided buffer's backing array")
	})

	t.Run("nil out still works", func(t *testing.T) {
		initM2 := newTestMachine(t, initCS, v, true, 4000)
		respM2 := newTestMachine(t, respCS, v, false, 5000)

		msg1, err := initM2.Initiate(nil)
		require.NoError(t, err)

		resp, _, err := respM2.ProcessPacket(nil, msg1)
		require.NoError(t, err)

		out, result, err := initM2.ProcessPacket(nil, resp)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Nil(t, out, "initiator should have no response for IX msg2")
	})
}

func TestMachineMsgIndexTracking(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	initCS := newTestCertState(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respCS := newTestCertState(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})
	v := testVerifier(caPool)

	initM := newTestMachine(t, initCS, v, true, 100)
	respM := newTestMachine(t, respCS, v, false, 200)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	resp1, result1, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	assert.NotNil(t, result1)

	_, result2, err := initM.ProcessPacket(nil, resp1)
	require.NoError(t, err)
	assert.NotNil(t, result2)
}

func TestMessageFlags(t *testing.T) {
	t.Run("IX", func(t *testing.T) {
		flags, err := messageFlags(header.HandshakeIXPSK0)
		require.NoError(t, err)
		require.Len(t, flags, 2)
		// msg1: payload + cert
		assert.True(t, flags[0].expectsPayload)
		assert.True(t, flags[0].expectsCert)
		// msg2: payload + cert
		assert.True(t, flags[1].expectsPayload)
		assert.True(t, flags[1].expectsCert)
	})

	t.Run("XX", func(t *testing.T) {
		registerTestXXFlags(t)
		flags, err := messageFlags(header.HandshakeXXPSK0)
		require.NoError(t, err)
		require.Len(t, flags, 3)
		// msg1: payload only
		assert.True(t, flags[0].expectsPayload)
		assert.False(t, flags[0].expectsCert)
		// msg2: payload + cert
		assert.True(t, flags[1].expectsPayload)
		assert.True(t, flags[1].expectsCert)
		// msg3: cert only
		assert.False(t, flags[2].expectsPayload)
		assert.True(t, flags[2].expectsCert)
	})

	t.Run("unknown subtype returns error", func(t *testing.T) {
		_, err := messageFlags(99)
		require.ErrorIs(t, err, ErrUnknownSubtype)
	})
}

func TestMachineThreeMessagePattern(t *testing.T) {
	registerTestXXFlags(t)

	// Use HandshakeXX (3 messages) to verify the Machine handles multi-message
	// patterns correctly. XX flow:
	//   msg1 (I->R): [E]           - payload only, no cert
	//   msg2 (R->I): [E, ee, S, es] - payload + cert
	//   msg3 (I->R): [S, se]       - cert only (no payload, not first two)

	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	initCS := newTestCertState(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	respCS := newTestCertState(t, ca, caKey, "resp", []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")})

	// Build HandshakeStates with XX pattern
	initHS, err := initCS.getCredential(cert.Version2).NewHandshakeState(true, noise.HandshakeXX)
	require.NoError(t, err)

	respHS, err := respCS.getCredential(cert.Version2).NewHandshakeState(false, noise.HandshakeXX)
	require.NoError(t, err)

	initM, err := NewMachine(
		initHS, cert.Version2,
		initCS.getCredential, v,
		func() (uint32, error) { return 1000, nil },
		true, header.HandshakeXXPSK0,
	)
	require.NoError(t, err)

	respM, err := NewMachine(
		respHS, cert.Version2,
		respCS.getCredential, v,
		func() (uint32, error) { return 2000, nil },
		false, header.HandshakeXXPSK0,
	)
	require.NoError(t, err)

	// msg1: initiator -> responder (E only, no cert)
	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)
	assert.NotEmpty(t, msg1)

	// Responder processes msg1, should not complete yet, should produce msg2
	msg2, result, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	assert.Nil(t, result, "XX should not complete on msg1")
	assert.NotEmpty(t, msg2, "responder should produce msg2")

	// Initiator processes msg2: gets responder's cert, produces msg3, and
	// completes (WriteMessage for msg3 derives keys)
	msg3, initResult, err := initM.ProcessPacket(nil, msg2)
	require.NoError(t, err)
	require.NotNil(t, initResult, "XX initiator should complete after reading msg2 and writing msg3")
	assert.NotEmpty(t, msg3, "initiator should produce msg3")
	assert.Equal(t, "resp", initResult.RemoteCert.Certificate.Name())

	// Responder processes msg3: gets initiator's cert and completes
	_, respResult, err := respM.ProcessPacket(nil, msg3)
	require.NoError(t, err)
	require.NotNil(t, respResult, "XX responder should complete on msg3")
	assert.Equal(t, "init", respResult.RemoteCert.Certificate.Name())

	assert.Equal(t, uint64(3), initResult.MessageIndex, "XX has 3 messages")
	assert.Equal(t, uint64(3), respResult.MessageIndex, "XX has 3 messages")

	// Verify keys work
	ct1, err := initResult.EKey.Encrypt(nil, nil, []byte("three messages"))
	require.NoError(t, err)
	pt1, err := respResult.DKey.Decrypt(nil, nil, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("three messages"), pt1)
}

// NOTE: ErrIncompleteHandshake is tested implicitly. It can't be triggered with
// IX since the cert is always in the payload. A 3-message pattern test (HybridIX)
// should exercise the case where cert arrives in msg3 and verify that completing
// without it fails.

func TestMachineExpiredCert(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519,
		time.Now().Add(-24*time.Hour), time.Now().Add(24*time.Hour),
		nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	expCert, _, expKeyPEM, _ := ct.NewTestCert(
		cert.Version2, cert.Curve_CURVE25519, ca, caKey,
		"expired", time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour),
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, nil, nil,
	)
	expKey, _, _, err := cert.UnmarshalPrivateKeyFromPEM(expKeyPEM)
	require.NoError(t, err)
	expHsBytes, err := expCert.MarshalForHandshakes()
	require.NoError(t, err)
	ncs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	expiredCS := &testCertState{
		version: cert.Version2,
		creds: map[cert.Version]*HandshakeCredential{
			cert.Version2: NewHandshakeCredential(expCert, expHsBytes, expKey, ncs),
		},
	}

	respCS := newTestCertState(
		t, ca, caKey, "responder",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
	)

	_, respM, _, _, err := initiateHandshake(
		t, expiredCS, testVerifier(caPool),
		respCS, testVerifier(caPool),
	)
	require.ErrorContains(t, err, "verify cert")
	assert.True(t, respM.Failed())
}

func TestMachineNoCertNetworks(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	caHsBytes, err := ca.MarshalForHandshakes()
	require.NoError(t, err)
	ncs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	noNetCS := &testCertState{
		version: cert.Version2,
		creds: map[cert.Version]*HandshakeCredential{
			cert.Version2: NewHandshakeCredential(ca, caHsBytes, caKey, ncs),
		},
	}

	respCS := newTestCertState(
		t, ca, caKey, "responder",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
	)

	_, respM, _, _, err := initiateHandshake(
		t, noNetCS, testVerifier(caPool),
		respCS, testVerifier(caPool),
	)
	require.Error(t, err)
	assert.True(t, respM.Failed())
}

func TestMachineDifferentCAs(t *testing.T) {
	ca1, _, caKey1, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	ca2, _, caKey2, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)

	initCS := newTestCertState(
		t, ca1, caKey1, "init",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	)
	respCS := newTestCertState(
		t, ca2, caKey2, "resp",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
	)

	_, respM, _, _, err := initiateHandshake(
		t, initCS, testVerifier(ct.NewTestCAPool(ca1)),
		respCS, testVerifier(ct.NewTestCAPool(ca2)),
	)
	require.ErrorContains(t, err, "verify cert")
	assert.True(t, respM.Failed())
}

func TestMachineVersionNegotiation(t *testing.T) {
	ca1, _, caKey1, _ := ct.NewTestCaCert(
		cert.Version1, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	ca2, _, caKey2, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca1, ca2)

	makeMultiVersionResp := func(t *testing.T) *testCertState {
		t.Helper()
		respCertV1, _, respKeyPEM, _ := ct.NewTestCert(
			cert.Version1, cert.Curve_CURVE25519, ca1, caKey1, "resp",
			ca1.NotBefore(), ca1.NotAfter(),
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}, nil, nil,
		)
		respKey, _, _, _ := cert.UnmarshalPrivateKeyFromPEM(respKeyPEM)
		respCertV2, _ := ct.NewTestCertDifferentVersion(respCertV1, cert.Version2, ca2, caKey2)
		respHsV1, _ := respCertV1.MarshalForHandshakes()
		respHsV2, _ := respCertV2.MarshalForHandshakes()
		ncs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
		return &testCertState{
			version: cert.Version1,
			creds: map[cert.Version]*HandshakeCredential{
				cert.Version1: NewHandshakeCredential(respCertV1, respHsV1, respKey, ncs),
				cert.Version2: NewHandshakeCredential(respCertV2, respHsV2, respKey, ncs),
			},
		}
	}

	t.Run("responder matches initiator version", func(t *testing.T) {
		initCS := newTestCertState(
			t, ca2, caKey2, "init",
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		)
		respCS := makeMultiVersionResp(t)
		v := testVerifier(caPool)

		initM, _, respResult, resp, err := initiateHandshake(
			t, initCS, v,
			respCS, v,
		)
		require.NoError(t, err)
		require.NotNil(t, respResult)

		assert.Equal(t, cert.Version2, respResult.MyCert.Version(),
			"responder should negotiate to initiator's version")

		_, initResult, err := initM.ProcessPacket(nil, resp)
		require.NoError(t, err)
		require.NotNil(t, initResult)
		assert.Equal(t, cert.Version2, initResult.RemoteCert.Certificate.Version(),
			"initiator should see V2 cert from responder")
	})

	t.Run("responder keeps version when no match available", func(t *testing.T) {
		initCS := newTestCertState(
			t, ca2, caKey2, "init",
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		)

		respCert, _, respKeyPEM, _ := ct.NewTestCert(
			cert.Version1, cert.Curve_CURVE25519, ca1, caKey1, "resp",
			ca1.NotBefore(), ca1.NotAfter(),
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}, nil, nil,
		)
		respKey, _, _, _ := cert.UnmarshalPrivateKeyFromPEM(respKeyPEM)
		respHs, _ := respCert.MarshalForHandshakes()
		ncs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
		respCS := &testCertState{
			version: cert.Version1,
			creds: map[cert.Version]*HandshakeCredential{
				cert.Version1: NewHandshakeCredential(respCert, respHs, respKey, ncs),
			},
		}

		v := testVerifier(caPool)
		_, _, respResult, _, err := initiateHandshake(
			t, initCS, v,
			respCS, v,
		)
		require.NoError(t, err)
		require.NotNil(t, respResult)

		assert.Equal(t, cert.Version1, respResult.MyCert.Version(),
			"responder should keep V1 when V2 not available")
	})
}
