package handshake

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/slackhq/nebula/cert"
	ct "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/noiseutil"
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

		// And the machine should still complete a real handshake afterward.
		_, result, err := initM.ProcessPacket(nil, resp)
		require.NoError(t, err)
		require.NotNil(t, result, "initiator should complete on the legitimate response")
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

	t.Run("subtype mismatch is recoverable", func(t *testing.T) {
		initCS := newTestCertState(t, ca, caKey, "init", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
		initM := newTestMachine(t, initCS, v, true, 100)
		msg1, err := initM.Initiate(nil)
		require.NoError(t, err)

		// Mutate the subtype byte (offset 1 in the header) to a value the
		// responder Machine wasn't built for.
		bad := make([]byte, len(msg1))
		copy(bad, msg1)
		bad[1] = 0xff

		respM := newTestMachine(t, cs, v, false, 200)
		_, _, err = respM.ProcessPacket(nil, bad)
		require.ErrorIs(t, err, ErrSubtypeMismatch)
		assert.False(t, respM.Failed(), "subtype mismatch should not kill the machine")

		// And the machine should still complete a real handshake afterward.
		resp, result, err := respM.ProcessPacket(nil, msg1)
		require.NoError(t, err)
		require.NotNil(t, result, "responder should complete on the legitimate stage-1 packet")
		assert.NotEmpty(t, resp, "responder should produce a stage-2 reply")
	})
}

// TestMachineProcessPayload exercises processPayload's internal validation
// directly. Most of these failure modes can't be reached black-box once the
// subtype check at the top of ProcessPacket gates external callers, so we
// drive them by hand here for coverage.
func TestMachineProcessPayload(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	cs := newTestCertState(t, ca, caKey, "test", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	v := testVerifier(caPool)

	t.Run("empty message with expects fails", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		err := m.processPayload(nil, msgFlags{expectsPayload: true, expectsCert: true})
		require.ErrorIs(t, err, ErrMissingContent)
		assert.True(t, m.Failed())
	})

	t.Run("empty message with no expects passes", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		err := m.processPayload(nil, msgFlags{})
		require.NoError(t, err)
		assert.False(t, m.Failed())
	})

	t.Run("malformed protobuf is fatal", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		err := m.processPayload([]byte{0xff, 0xff, 0xff}, msgFlags{expectsPayload: true, expectsCert: true})
		require.Error(t, err)
		assert.True(t, m.Failed())
	})

	t.Run("unexpected payload data is fatal", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		// A payload with index data when none was expected.
		bytes := MarshalPayload(nil, Payload{InitiatorIndex: 42, Time: 1})
		err := m.processPayload(bytes, msgFlags{expectsPayload: false, expectsCert: false})
		require.ErrorIs(t, err, ErrUnexpectedContent)
		assert.True(t, m.Failed())
	})

	t.Run("unexpected cert data is fatal", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		// A payload with cert when none was expected.
		bytes := MarshalPayload(nil, Payload{Cert: []byte{1, 2, 3}, CertVersion: 2})
		err := m.processPayload(bytes, msgFlags{expectsPayload: false, expectsCert: false})
		require.ErrorIs(t, err, ErrUnexpectedContent)
		assert.True(t, m.Failed())
	})

	t.Run("missing payload data when expected is fatal", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		// Cert present, but no index/time fields.
		bytes := MarshalPayload(nil, Payload{Cert: []byte{1, 2, 3}, CertVersion: 2})
		err := m.processPayload(bytes, msgFlags{expectsPayload: true, expectsCert: true})
		require.ErrorIs(t, err, ErrUnexpectedContent)
		assert.True(t, m.Failed())
	})

	t.Run("zero initiator index on responder is fatal", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		bytes := MarshalPayload(nil, Payload{InitiatorIndex: 0, Time: 1})
		err := m.processPayload(bytes, msgFlags{expectsPayload: true})
		require.ErrorIs(t, err, ErrInvalidRemoteIndex)
		assert.True(t, m.Failed())
		assert.Zero(t, m.result.RemoteIndex)
	})

	t.Run("zero responder index on initiator is fatal", func(t *testing.T) {
		m := newTestMachine(t, cs, v, true, 100)
		bytes := MarshalPayload(nil, Payload{InitiatorIndex: 100, ResponderIndex: 0, Time: 1})
		err := m.processPayload(bytes, msgFlags{expectsPayload: true})
		require.ErrorIs(t, err, ErrInvalidRemoteIndex)
		assert.True(t, m.Failed())
		assert.Zero(t, m.result.RemoteIndex)
	})
}

// TestMachineRequireComplete checks the fail-on-incomplete-handshake path
// directly. Like processPayload above this isn't reachable from a normal IX
// flow, so we drive it by hand.
func TestMachineRequireComplete(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	cs := newTestCertState(t, ca, caKey, "test", []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")})
	v := testVerifier(caPool)

	t.Run("missing both fails", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		err := m.requireComplete()
		require.ErrorIs(t, err, ErrIncompleteHandshake)
		assert.True(t, m.Failed())
	})

	t.Run("payload only fails", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		m.payloadSet = true
		err := m.requireComplete()
		require.ErrorIs(t, err, ErrIncompleteHandshake)
		assert.True(t, m.Failed())
	})

	t.Run("cert only fails", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		m.remoteCertSet = true
		err := m.requireComplete()
		require.ErrorIs(t, err, ErrIncompleteHandshake)
		assert.True(t, m.Failed())
	})

	t.Run("both set passes", func(t *testing.T) {
		m := newTestMachine(t, cs, v, false, 100)
		m.payloadSet = true
		m.remoteCertSet = true
		err := m.requireComplete()
		require.NoError(t, err)
		assert.False(t, m.Failed())
	})
}

func TestMachineAESCipher(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	initCS := newTestCertStateWithCipher(
		t, ca, caKey, "init",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		noiseutil.CipherAESGCM,
	)
	respCS := newTestCertStateWithCipher(
		t, ca, caKey, "resp",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
		noiseutil.CipherAESGCM,
	)

	initR, respR := doFullHandshake(t, initCS, respCS, caPool)

	ct1, err := initR.EKey.Encrypt(nil, nil, []byte("works"))
	require.NoError(t, err)
	pt1, err := respR.DKey.Decrypt(nil, nil, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("works"), pt1)

	ct2, err := respR.EKey.Encrypt(nil, nil, []byte("back"))
	require.NoError(t, err)
	pt2, err := initR.DKey.Decrypt(nil, nil, ct2)
	require.NoError(t, err)
	assert.Equal(t, []byte("back"), pt2)
}

func TestResultFields(t *testing.T) {
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

func TestMachineThreeMessagePattern(t *testing.T) {
	registerTestXXInfo(t)

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

	initM, err := NewMachine(
		cert.Version2,
		initCS.getCredential, v,
		func() (uint32, error) { return 1000, nil },
		true, header.HandshakeXXPSK0, nil, nil,
	)
	require.NoError(t, err)

	respM, err := NewMachine(
		cert.Version2,
		respCS.getCredential, v,
		func() (uint32, error) { return 2000, nil },
		false, header.HandshakeXXPSK0, nil, nil,
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
		creds: map[cert.Version]*Credential{
			cert.Version2: NewCredential(expCert, expHsBytes, expKey, ncs, nil),
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
		creds: map[cert.Version]*Credential{
			cert.Version2: NewCredential(ca, caHsBytes, caKey, ncs, nil),
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
			creds: map[cert.Version]*Credential{
				cert.Version1: NewCredential(respCertV1, respHsV1, respKey, ncs, nil),
				cert.Version2: NewCredential(respCertV2, respHsV2, respKey, ncs, nil),
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
			creds: map[cert.Version]*Credential{
				cert.Version1: NewCredential(respCert, respHs, respKey, ncs, nil),
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

// TestMachineIXPSK_HappyPath verifies that when both peers carry the same
// 32-byte PQ PSK, the IX handshake completes and produces working session
// keys. flynn/noise rewrites the protocol_name from Noise_IX_... to
// Noise_IXpsk0_... when PresharedKey is non-empty, but the wire format that
// nebula cares about (subtype byte, packet sizes) is unchanged.
func TestMachineIXPSK_HappyPath(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)

	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i)
	}

	initCS := newTestCertStateWithPSK(t, ca, caKey, "initiator",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		noise.CipherChaChaPoly, psk)
	respCS := newTestCertStateWithPSK(t, ca, caKey, "responder",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
		noise.CipherChaChaPoly, psk)

	initR, respR := doFullHandshake(t, initCS, respCS, caPool)

	assert.Equal(t, "responder", initR.RemoteCert.Certificate.Name())
	assert.Equal(t, "initiator", respR.RemoteCert.Certificate.Name())

	ct1, err := initR.EKey.Encrypt(nil, nil, []byte("hello-pq"))
	require.NoError(t, err)
	pt1, err := respR.DKey.Decrypt(nil, nil, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello-pq"), pt1)
}

// TestMachineIXPSK_Mismatch verifies that if the two peers disagree on the
// PSK (or one has it and the other does not), the handshake fails before
// any session keys are produced. This is the safety net for a misconfigured
// or partially-rolled-out mesh.
func TestMachineIXPSK_Mismatch(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	pskA := make([]byte, 32)
	for i := range pskA {
		pskA[i] = 0xAA
	}
	pskB := make([]byte, 32)
	for i := range pskB {
		pskB[i] = 0xBB
	}

	// wantErr pins each failure to the layer it must surface at. When
	// both sides run psk0 (or only the responder does), the responder
	// decrypts msg1 with a PSK-derived key and the disagreement is an
	// AEAD failure inside noise. When only the initiator has a PSK the
	// responder runs plain IX — msg1's payload reads as undecrypted
	// garbage and fails at payload unmarshal instead. Either way the
	// handshake must die before key derivation; these substrings catch
	// a regression that silently moves (or removes) the failure.
	cases := []struct {
		name             string
		initPSK, respPSK []byte
		wantErr          string
	}{
		{"different PSKs", pskA, pskB, "noise ReadMessage"},
		{"only initiator has PSK", pskA, nil, "unmarshal handshake"},
		{"only responder has PSK", nil, pskA, "noise ReadMessage"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initCS := newTestCertStateWithPSK(t, ca, caKey, "initiator",
				[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
				noise.CipherChaChaPoly, tc.initPSK)
			respCS := newTestCertStateWithPSK(t, ca, caKey, "responder",
				[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
				noise.CipherChaChaPoly, tc.respPSK)

			initM := newTestMachine(t, initCS, v, true, 1000)
			respM := newTestMachine(t, respCS, v, false, 2000)

			msg1, err := initM.Initiate(nil)
			require.NoError(t, err)

			_, _, err = respM.ProcessPacket(nil, msg1)
			require.Error(t, err, "responder must reject msg1 when PSKs disagree")
			assert.Contains(t, err.Error(), tc.wantErr,
				"PSK disagreement must fail at the expected layer")
		})
	}

	_ = noiseutil.CipherAESGCM // keep import alive for future PSK+AES test
}

// TestMachineIXPSK2_HappyPath exercises the per-peer PSK path. Initiator
// presets the PSK keyed by the responder's static; responder learns the
// initiator's static from msg1 and looks up the matching PSK before
// producing msg2.
func TestMachineIXPSK2_HappyPath(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 0x42
	}

	// Both sides share the same lookup func: any peer-static -> the test
	// PSK. Real deployments key by SHA-256(peer-static); this stub is
	// sufficient to exercise the placement-2 wiring. The peer-cert arg
	// is ignored at this layer of the test.
	// Returns a copy so that wipeBytes in buildHandshakeState / injectResponderPSK
	// does not zero the test's underlying psk variable (mirroring real providers
	// which always return freshly-allocated copies).
	lookup := func([]byte, cert.Certificate) []byte { return append([]byte{}, psk...) }

	initCS := newTestCertStateWithPSKLookup(t, ca, caKey, "init",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		noise.CipherChaChaPoly, lookup)
	respCS := newTestCertStateWithPSKLookup(t, ca, caKey, "resp",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
		noise.CipherChaChaPoly, lookup)

	respStatic := respCS.creds[cert.Version2].Cert.PublicKey()

	initM := newTestMachineWithSubtype(t, initCS, v, true, 1000, header.HandshakeIXPSK2, respStatic)
	respM := newTestMachineWithSubtype(t, respCS, v, false, 2000, header.HandshakeIXPSK2, nil)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	resp, respResult, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.NotNil(t, respResult, "responder should complete on msg2 send")
	require.NotEmpty(t, resp)

	_, initResult, err := initM.ProcessPacket(nil, resp)
	require.NoError(t, err)
	require.NotNil(t, initResult, "initiator should complete on msg2 read")

	// Verify session keys actually work end-to-end with the PSK mixed in.
	ct1, err := initResult.EKey.Encrypt(nil, nil, []byte("psk2-hello"))
	require.NoError(t, err)
	pt1, err := respResult.DKey.Decrypt(nil, nil, ct1)
	require.NoError(t, err)
	assert.Equal(t, []byte("psk2-hello"), pt1)
}

// TestMachineIXPSK2_ResponderMissingPSK confirms that a responder which has
// no PSK configured for the calling peer rejects the handshake rather than
// silently downgrading.
func TestMachineIXPSK2_ResponderMissingPSK(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	psk := make([]byte, 32)
	// Initiator has a PSK keyed by responder static.
	initLookup := func([]byte, cert.Certificate) []byte { return append([]byte{}, psk...) }
	// Responder lookup returns nil for all peers — simulating "no PSK file
	// matched the initiator's static fingerprint".
	respLookup := func([]byte, cert.Certificate) []byte { return nil }

	initCS := newTestCertStateWithPSKLookup(t, ca, caKey, "init",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		noise.CipherChaChaPoly, initLookup)
	respCS := newTestCertStateWithPSKLookup(t, ca, caKey, "resp",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
		noise.CipherChaChaPoly, respLookup)

	respStatic := respCS.creds[cert.Version2].Cert.PublicKey()
	initM := newTestMachineWithSubtype(t, initCS, v, true, 1000, header.HandshakeIXPSK2, respStatic)
	respM := newTestMachineWithSubtype(t, respCS, v, false, 2000, header.HandshakeIXPSK2, nil)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	_, _, err = respM.ProcessPacket(nil, msg1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no psk configured")
}

// TestMachineIXPSK2_PSKMismatch confirms that two peers carrying different
// PSKs for each other still produce an authentication failure on msg2 read,
// not silently completing.
func TestMachineIXPSK2_PSKMismatch(t *testing.T) {
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	pskA := make([]byte, 32)
	pskB := make([]byte, 32)
	for i := range pskA {
		pskA[i] = 0xAA
		pskB[i] = 0xBB
	}

	initCS := newTestCertStateWithPSKLookup(t, ca, caKey, "init",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		noise.CipherChaChaPoly, func([]byte, cert.Certificate) []byte { return append([]byte{}, pskA...) })
	respCS := newTestCertStateWithPSKLookup(t, ca, caKey, "resp",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
		noise.CipherChaChaPoly, func([]byte, cert.Certificate) []byte { return append([]byte{}, pskB...) })

	respStatic := respCS.creds[cert.Version2].Cert.PublicKey()
	initM := newTestMachineWithSubtype(t, initCS, v, true, 1000, header.HandshakeIXPSK2, respStatic)
	respM := newTestMachineWithSubtype(t, respCS, v, false, 2000, header.HandshakeIXPSK2, nil)

	msg1, err := initM.Initiate(nil)
	require.NoError(t, err)

	// msg1 has no PSK token (placement 2 puts it on msg2), so responder
	// reads msg1 + injects its own (wrong) PSK + writes msg2 successfully.
	resp, _, err := respM.ProcessPacket(nil, msg1)
	require.NoError(t, err)
	require.NotEmpty(t, resp)

	// Initiator hits the PSK mismatch when it processes msg2: the PSK
	// token at the end mixes pskA on initiator's side, pskB on responder's
	// side, so the AEAD tag on msg2's payload fails.
	_, _, err = initM.ProcessPacket(nil, resp)
	require.Error(t, err)
}

// newPSK2TestPair builds a matched IXPSK2 initiator/responder pair where
// the initiator is pre-seeded with initiatorPSK and the responder's lookup
// returns responderPSK. The two PSKs may differ (epoch-skew scenarios).
func newPSK2TestPair(t *testing.T, initiatorPSK, responderPSK []byte) (init, resp *Machine) {
	t.Helper()
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	// Return copies so wipeBytes does not zero the caller's psk slices
	// (mirroring real providers which always return freshly-allocated copies).
	initLookup := func([]byte, cert.Certificate) []byte { return append([]byte{}, initiatorPSK...) }
	respLookup := func([]byte, cert.Certificate) []byte { return append([]byte{}, responderPSK...) }

	initCS := newTestCertStateWithPSKLookup(t, ca, caKey, "init",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		noise.CipherChaChaPoly, initLookup)
	respCS := newTestCertStateWithPSKLookup(t, ca, caKey, "resp",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
		noise.CipherChaChaPoly, respLookup)

	respStatic := respCS.creds[cert.Version2].Cert.PublicKey()

	init = newTestMachineWithSubtype(t, initCS, v, true, 1000, header.HandshakeIXPSK2, respStatic)
	resp = newTestMachineWithSubtype(t, respCS, v, false, 2000, header.HandshakeIXPSK2, nil)
	return
}

// newPSK2TestPairWithPrev is like newPSK2TestPair but also installs a
// previous-epoch PSK lookup on the responder's credential. The initiator's
// PSK and the responder's current and previous PSKs may all differ.
func newPSK2TestPairWithPrev(t *testing.T, initiatorPSK, respCurrentPSK, respPrevPSK []byte) (init, resp *Machine) {
	t.Helper()
	ca, _, caKey, _ := ct.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519, time.Time{}, time.Time{}, nil, nil, nil,
	)
	caPool := ct.NewTestCAPool(ca)
	v := testVerifier(caPool)

	// Return copies so wipeBytes does not zero the caller's psk slices
	// (mirroring real providers which always return freshly-allocated copies).
	initLookup := func([]byte, cert.Certificate) []byte { return append([]byte{}, initiatorPSK...) }
	respLookup := func([]byte, cert.Certificate) []byte { return append([]byte{}, respCurrentPSK...) }
	respPrevLookup := func([]byte, cert.Certificate) []byte { return append([]byte{}, respPrevPSK...) }

	initCS := newTestCertStateWithPSKLookup(t, ca, caKey, "init",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		noise.CipherChaChaPoly, initLookup)
	respCS := newTestCertStateWithPSKLookup(t, ca, caKey, "resp",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")},
		noise.CipherChaChaPoly, respLookup)

	// Install prev lookup on the responder's credential.
	respCS.creds[cert.Version2].SetPSKLookupPrev(respPrevLookup)

	respStatic := respCS.creds[cert.Version2].Cert.PublicKey()

	init = newTestMachineWithSubtype(t, initCS, v, true, 1000, header.HandshakeIXPSK2, respStatic)
	resp = newTestMachineWithSubtype(t, respCS, v, false, 2000, header.HandshakeIXPSK2, nil)
	return
}

func TestMachine_SwapPSKHealsInitiator(t *testing.T) {
	// Initiator configured with WRONG psk (epoch B), responder with
	// epoch A. msg2 must fail, then succeed after SwapPSK(epochA) on
	// the SAME msg2 bytes — proving noise rollback + swap works.
	pskA := bytes.Repeat([]byte{0xA1}, 32)
	pskB := bytes.Repeat([]byte{0xB2}, 32)

	init, resp := newPSK2TestPair(t, pskB, pskA)

	msg1, err := init.Initiate(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg2, result, err := resp.ProcessPacket(nil, msg1)
	if err != nil || result == nil {
		t.Fatalf("responder: %v", err)
	}

	_, _, err = init.ProcessPacket(nil, msg2)
	if err == nil {
		t.Fatal("expected msg2 AEAD failure with mismatched PSK")
	}
	if init.Failed() {
		t.Fatal("machine must survive a msg2 AEAD failure (noise rolls back)")
	}

	if err := init.SwapPSK(pskA); err != nil {
		t.Fatal(err)
	}
	_, result, err = init.ProcessPacket(nil, msg2)
	if err != nil || result == nil {
		t.Fatalf("after SwapPSK, same msg2 must complete: %v", err)
	}
}

func TestMachine_SwapPSKGuards(t *testing.T) {
	pskA := bytes.Repeat([]byte{0xA1}, 32)
	init, resp := newPSK2TestPair(t, pskA, pskA)
	if err := resp.SwapPSK(pskA); err == nil {
		t.Fatal("SwapPSK on responder must error")
	}
	if err := init.SwapPSK(pskA); err == nil {
		t.Fatal("SwapPSK before Initiate must error")
	}
	// After a successful swap, a second swap must error (one per machine).
	msg1, _ := init.Initiate(nil)
	_ = msg1
	if err := init.SwapPSK(pskA); err != nil {
		t.Fatalf("first swap while waiting for msg2: %v", err)
	}
	if err := init.SwapPSK(pskA); err == nil {
		t.Fatal("second SwapPSK must error")
	}

	// Post-completion: run a full successful IXPSK2 handshake, then verify
	// that SwapPSK on the completed initiator errors (MessageIndex is 2,
	// not 1, so the machine is no longer waiting for msg2).
	init2, resp2 := newPSK2TestPair(t, pskA, pskA)
	msg1b, err := init2.Initiate(nil)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	msg2b, respResult, err := resp2.ProcessPacket(nil, msg1b)
	if err != nil || respResult == nil {
		t.Fatalf("responder ProcessPacket: %v", err)
	}
	_, initResult, err := init2.ProcessPacket(nil, msg2b)
	if err != nil || initResult == nil {
		t.Fatalf("initiator ProcessPacket: %v", err)
	}
	// Handshake is complete; MessageIndex is 2. SwapPSK must now reject.
	if err := init2.SwapPSK(pskA); err == nil {
		t.Fatal("SwapPSK after completion must error (MessageIndex is 2, not 1)")
	}
}

func TestMachine_ResponderPrefersPreviousPSK(t *testing.T) {
	pskOld := bytes.Repeat([]byte{0x01}, 32)
	pskNew := bytes.Repeat([]byte{0x02}, 32)
	// Initiator holds OLD epoch; responder current=NEW, prev=OLD.
	init, resp := newPSK2TestPairWithPrev(t, pskOld, pskNew, pskOld)
	resp.SetResponderPSKChooser(func(peerStatic []byte) bool { return true })

	msg1, err := init.Initiate(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg2, result, err := resp.ProcessPacket(nil, msg1)
	if err != nil || result == nil {
		t.Fatalf("responder with prev-chooser: %v", err)
	}
	if !resp.UsedPreviousPSK() {
		t.Fatal("UsedPreviousPSK must report true")
	}
	if _, result, err = init.ProcessPacket(nil, msg2); err != nil || result == nil {
		t.Fatalf("initiator must accept msg2 mixed with previous epoch: %v", err)
	}
}

func TestMachine_ResponderChooserFallsBackToCurrent(t *testing.T) {
	psk := bytes.Repeat([]byte{0x03}, 32)
	// Chooser says "use previous" but responder cred has NO prev lookup:
	// must fall back to current and complete normally.
	init, resp := newPSK2TestPair(t, psk, psk)
	resp.SetResponderPSKChooser(func([]byte) bool { return true })
	msg1, _ := init.Initiate(nil)
	msg2, result, err := resp.ProcessPacket(nil, msg1)
	if err != nil || result == nil {
		t.Fatalf("responder must fall back to current psk: %v", err)
	}
	if resp.UsedPreviousPSK() {
		t.Fatal("fallback to current must not report UsedPreviousPSK")
	}
	if _, result, err = init.ProcessPacket(nil, msg2); err != nil || result == nil {
		t.Fatalf("handshake must complete: %v", err)
	}
}
