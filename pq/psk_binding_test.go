package pq

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubCert is a minimal cert.Certificate that returns a configurable
// PqPskBinding. Every other accessor returns a zero value;
// ValidatePSKBinding only consults PqPskBinding, so a richer
// test double would just add noise.
type stubCert struct {
	rpHash []byte
}

func (s *stubCert) Version() cert.Version                     { return cert.Version2 }
func (s *stubCert) Name() string                              { return "" }
func (s *stubCert) Networks() []netip.Prefix                  { return nil }
func (s *stubCert) UnsafeNetworks() []netip.Prefix            { return nil }
func (s *stubCert) Groups() []string                          { return nil }
func (s *stubCert) IsCA() bool                                { return false }
func (s *stubCert) NotBefore() time.Time                      { return time.Time{} }
func (s *stubCert) NotAfter() time.Time                       { return time.Time{} }
func (s *stubCert) Issuer() string                            { return "" }
func (s *stubCert) PublicKey() []byte                         { return nil }
func (s *stubCert) MarshalPublicKeyPEM() []byte               { return nil }
func (s *stubCert) Curve() cert.Curve                         { return cert.Curve_CURVE25519 }
func (s *stubCert) PqPskBinding() []byte                      { return s.rpHash }
func (s *stubCert) Signature() []byte                         { return nil }
func (s *stubCert) CheckSignature([]byte) bool                { return false }
func (s *stubCert) Fingerprint() (string, error)              { return "", nil }
func (s *stubCert) Expired(time.Time) bool                    { return false }
func (s *stubCert) VerifyPrivateKey(cert.Curve, []byte) error { return nil }
func (s *stubCert) Marshal() ([]byte, error)                  { return nil, nil }
func (s *stubCert) MarshalForHandshakes() ([]byte, error)     { return nil, nil }
func (s *stubCert) MarshalPEM() ([]byte, error)               { return nil, nil }
func (s *stubCert) MarshalJSON() ([]byte, error)              { return nil, nil }
func (s *stubCert) String() string                            { return "" }
func (s *stubCert) Copy() cert.Certificate                    { c := *s; return &c }

// mustHashBytes returns a 32-byte slice whose value is hex-decoded
// from s. The string must be exactly 64 hex chars.
func mustHashBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.Len(t, b, cert.PqPskBindingLen)
	return b
}

// captureLogger returns an slog.Logger writing JSON to a buffer the
// caller can inspect after the call. Each line is one event.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), buf
}

func TestParsePqPskBindingMode(t *testing.T) {
	cases := map[string]PqPskBindingMode{
		"":         PqPskBindingWarn,
		"warn":     PqPskBindingWarn,
		"WARN":     PqPskBindingWarn,
		"  warn ":  PqPskBindingWarn,
		"off":      PqPskBindingOff,
		"disabled": PqPskBindingOff,
		"enforce":  PqPskBindingEnforce,
		"strict":   PqPskBindingEnforce,
	}
	for in, want := range cases {
		got, err := ParsePqPskBindingMode(in)
		require.NoError(t, err, "input %q", in)
		assert.Equal(t, want, got, "input %q", in)
	}
	_, err := ParsePqPskBindingMode("rubbish")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "psk_binding")
}

func TestPqPskBindingModeString(t *testing.T) {
	cases := map[PqPskBindingMode]string{
		PqPskBindingOff:     "off",
		PqPskBindingWarn:    "warn",
		PqPskBindingEnforce: "enforce",
	}
	for m, want := range cases {
		assert.Equal(t, want, m.String())
	}
}

// TestValidatePSKBinding_AllCases pins the tri-state matrix from the
// gap-2 spec. Every combination of (mode, cert hash present, rpinfo
// present, match/mismatch) is asserted to either use the PSK or refuse
// it, plus the expected log level for cases that should warn / error.
func TestValidatePSKBinding_AllCases(t *testing.T) {
	hashA := strings.Repeat("a", 64) // 32-byte hex
	hashB := strings.Repeat("b", 64)

	cases := []struct {
		name     string
		mode     PqPskBindingMode
		certHash string // "" means no cert (or cert ext absent)
		rpHash   string // "" means no rpinfo
		wantUsed bool   // true = ValidatePSKBinding returns true (PSK used)
		wantLog  string // substring that must appear in the captured log, or "" for silent
	}{
		// off: always use, never log
		{"off_all_absent", PqPskBindingOff, "", "", true, ""},
		{"off_cert_only", PqPskBindingOff, hashA, "", true, ""},
		{"off_rpinfo_only", PqPskBindingOff, "", hashA, true, ""},
		{"off_mismatch", PqPskBindingOff, hashA, hashB, true, ""},
		{"off_match", PqPskBindingOff, hashA, hashA, true, ""},

		// warn: always use; log varies by combination
		{"warn_all_absent", PqPskBindingWarn, "", "", true, ""},
		{"warn_rpinfo_only", PqPskBindingWarn, "", hashA, true, "provider binding hint present but peer cert has no PQ-PSK binding"},
		{"warn_cert_only", PqPskBindingWarn, hashA, "", true, "peer cert claims PQ-PSK binding but no provider binding hint present"},
		{"warn_mismatch", PqPskBindingWarn, hashA, hashB, true, "PQ-PSK binding mismatch"},
		{"warn_match", PqPskBindingWarn, hashA, hashA, true, ""},

		// enforce: refuse on cert-claim + missing/mismatch
		{"enforce_all_absent", PqPskBindingEnforce, "", "", true, ""},
		{"enforce_rpinfo_only", PqPskBindingEnforce, "", hashA, true, "provider binding hint present but peer cert has no PQ-PSK binding"},
		{"enforce_cert_only_REFUSE", PqPskBindingEnforce, hashA, "", false, "refusing PSK; peer cert claims PQ-PSK binding but no provider binding hint present"},
		{"enforce_mismatch_REFUSE", PqPskBindingEnforce, hashA, hashB, false, "refusing PSK; PQ-PSK binding mismatch"},
		{"enforce_match", PqPskBindingEnforce, hashA, hashA, true, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := captureLogger()
			var peerCert cert.Certificate
			if tc.certHash != "" {
				peerCert = &stubCert{rpHash: mustHashBytes(t, tc.certHash)}
			}
			got := ValidatePSKBinding(tc.mode, peerCert, tc.rpHash, logger)
			assert.Equal(t, tc.wantUsed, got, "binding decision")
			if tc.wantLog == "" {
				assert.Empty(t, buf.String(), "expected no log output for %s; got: %s", tc.name, buf.String())
			} else {
				assert.Contains(t, buf.String(), tc.wantLog, "log substring for %s", tc.name)
			}
		})
	}
}

// TestValidatePSKBinding_NilLoggerDoesNotPanic ensures the helper can
// be called from a test path that doesn't bother wiring a logger.
func TestValidatePSKBinding_NilLoggerDoesNotPanic(t *testing.T) {
	peerCert := &stubCert{rpHash: mustHashBytes(t, strings.Repeat("a", 64))}
	// enforce + cert-only triggers an Error log path; nil logger must
	// elide it without panicking.
	assert.False(t, ValidatePSKBinding(PqPskBindingEnforce, peerCert, "", nil))
	assert.True(t, ValidatePSKBinding(PqPskBindingWarn, peerCert, "", nil))
}

// TestValidatePSKBinding_NilCertTreatedAsNoClaim mirrors the initiator
// boot path where no cached cert is in hand: nil cert + present rpinfo
// must use the PSK in every mode (there's no claim to enforce against).
func TestValidatePSKBinding_NilCertTreatedAsNoClaim(t *testing.T) {
	rpHash := strings.Repeat("a", 64)
	for _, mode := range []PqPskBindingMode{PqPskBindingOff, PqPskBindingWarn, PqPskBindingEnforce} {
		t.Run(mode.String(), func(t *testing.T) {
			assert.True(t, ValidatePSKBinding(mode, nil, rpHash, nil),
				"nil cert + rpinfo must always use PSK regardless of mode")
			assert.True(t, ValidatePSKBinding(mode, nil, "", nil),
				"nil cert + no rpinfo must always use PSK regardless of mode")
		})
	}
}

// TestValidatePSKBinding_WrongLengthCertHashIgnored verifies that a v2
// cert with a malformed (wrong-length) PqPskBinding is treated
// as "no claim" rather than crashing on hex encoding or being matched
// against any rpinfo. The cert package already rejects malformed certs
// at parse time, so this is defence-in-depth.
func TestValidatePSKBinding_WrongLengthCertHashIgnored(t *testing.T) {
	peerCert := &stubCert{rpHash: []byte{0x01, 0x02, 0x03}} // not 32 bytes
	logger, buf := captureLogger()
	// In enforce mode with a "claim" that's actually malformed, we
	// behave as if no extension were present. rpinfo absent -> silent
	// use-PSK.
	assert.True(t, ValidatePSKBinding(PqPskBindingEnforce, peerCert, "", logger))
	assert.Empty(t, buf.String(), "malformed cert ext must be ignored, not logged at enforce level")
}

// TestValidatePSKBindingInputs_WithGossipedHash_TruthTable pins the
// expanded matrix that includes the gossiped-hash dimension. Cert is
// authoritative; gossip and rpinfo are supporting evidence; under
// enforce mode any disagreement with cert is a hard refuse.
func TestValidatePSKBindingInputs_WithGossipedHash_TruthTable(t *testing.T) {
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)

	cases := []struct {
		name     string
		mode     PqPskBindingMode
		certHash string
		gossip   string
		rpinfo   string
		wantUsed bool
		wantLog  string // substring; "" means silent
	}{
		// off: always silent, always use, regardless of inputs.
		{"off_all_disagree", PqPskBindingOff, hashA, hashB, hashB, true, ""},
		{"off_cert_only", PqPskBindingOff, hashA, "", "", true, ""},

		// All three present and agree: silent (steady state).
		{"warn_all_three_agree", PqPskBindingWarn, hashA, hashA, hashA, true, ""},
		{"enforce_all_three_agree", PqPskBindingEnforce, hashA, hashA, hashA, true, ""},

		// Cert present + only gossip + agree: gossip is unsigned peer
		// self-report and no longer counts as confirming evidence — only
		// the operator-controlled rpinfo can confirm a cert claim. So
		// this collapses to "cert alone" semantics: warn allows + logs
		// the no-rpinfo state, enforce refuses for the same reason.
		{"warn_cert_gossip_agree", PqPskBindingWarn, hashA, hashA, "", true, "peer cert claims PQ-PSK binding but no provider binding hint present"},
		{"enforce_cert_gossip_agree", PqPskBindingEnforce, hashA, hashA, "", false, "refusing PSK; peer cert claims PQ-PSK binding but no provider binding hint present"},

		// Cert present + only gossip + disagree: cert is authoritative,
		// gossip is peer self-report (unsigned), so the gossip mismatch
		// is logged-but-not-enforced. The PSK decision falls through to
		// the rpinfo check; here rpinfo is absent so warn allows (with
		// the no-rpinfo warn log) and enforce refuses (on rpinfo-absent,
		// NOT on gossip — preventing a compromised peer or lighthouse
		// from using gossip to DoS a peer's PSK).
		{"warn_cert_gossip_disagree", PqPskBindingWarn, hashA, hashB, "", true, "ignoring gossip; cert is authoritative"},
		{"enforce_cert_gossip_disagree", PqPskBindingEnforce, hashA, hashB, "", false, "refusing PSK; peer cert claims PQ-PSK binding but no provider binding hint present"},

		// Cert present + only rpinfo + disagree: rpinfo is operator-
		// controlled, so it CAN refuse under enforce mode.
		{"warn_cert_rpinfo_disagree", PqPskBindingWarn, hashA, "", hashB, true, "PQ-PSK binding mismatch"},
		{"enforce_cert_rpinfo_disagree", PqPskBindingEnforce, hashA, "", hashB, false, "refusing PSK; PQ-PSK binding mismatch"},

		// Cert present + gossip matches + rpinfo disagrees: cert+gossip agree, rpinfo is the dissent.
		{"warn_cert_match_rpinfo_disagree", PqPskBindingWarn, hashA, hashA, hashB, true, "PQ-PSK binding mismatch"},
		{"enforce_cert_match_rpinfo_disagree", PqPskBindingEnforce, hashA, hashA, hashB, false, "refusing PSK; PQ-PSK binding mismatch"},

		// Cert present + gossip disagrees + rpinfo MATCHES cert: cert is
		// authoritative, rpinfo confirms it, so the PSK is used in both
		// modes. The gossip mismatch is logged (peer is lying about
		// itself) but does NOT refuse — this is the core of the DoS
		// hardening: a compromised peer cannot use gossip to refuse its
		// own (or anyone else's) PSK once the cert + rpinfo agree.
		{"warn_cert_gossip_disagree_rpinfo_match", PqPskBindingWarn, hashA, hashB, hashA, true, "ignoring gossip; cert is authoritative"},
		{"enforce_cert_gossip_disagree_rpinfo_match", PqPskBindingEnforce, hashA, hashB, hashA, true, "ignoring gossip; cert is authoritative"},

		// Cert absent: gossip and rpinfo are unsigned signals. Never refuses.
		{"warn_no_cert_gossip_only", PqPskBindingWarn, "", hashA, "", true, ""},
		{"enforce_no_cert_gossip_only", PqPskBindingEnforce, "", hashA, "", true, ""},
		{"warn_no_cert_gossip_rpinfo_agree", PqPskBindingWarn, "", hashA, hashA, true, ""},
		{"enforce_no_cert_gossip_rpinfo_agree", PqPskBindingEnforce, "", hashA, hashA, true, ""},
		{"warn_no_cert_gossip_rpinfo_disagree", PqPskBindingWarn, "", hashA, hashB, true, "gossip/provider PQ-PSK binding disagree"},
		{"enforce_no_cert_gossip_rpinfo_disagree", PqPskBindingEnforce, "", hashA, hashB, true, "gossip/provider PQ-PSK binding disagree"},
		{"warn_no_cert_rpinfo_only", PqPskBindingWarn, "", "", hashA, true, "provider binding hint present but peer cert has no PQ-PSK binding"},
		{"enforce_no_cert_rpinfo_only", PqPskBindingEnforce, "", "", hashA, true, "provider binding hint present but peer cert has no PQ-PSK binding"},

		// Cert present + no supporting evidence: enforce refuses, warn logs.
		{"warn_cert_alone", PqPskBindingWarn, hashA, "", "", true, "peer cert claims PQ-PSK binding but no provider binding hint present"},
		{"enforce_cert_alone_REFUSE", PqPskBindingEnforce, hashA, "", "", false, "refusing PSK; peer cert claims PQ-PSK binding but no provider binding hint present"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := captureLogger()
			in := BindingInputs{
				CertHash:        tc.certHash,
				GossipedHash:    tc.gossip,
				LocalProviderHash: tc.rpinfo,
			}
			got := ValidatePSKBindingInputs(tc.mode, in, logger)
			assert.Equal(t, tc.wantUsed, got, "binding decision for %s", tc.name)
			if tc.wantLog == "" {
				assert.Empty(t, buf.String(), "expected no log output for %s; got: %s", tc.name, buf.String())
			} else {
				assert.Contains(t, buf.String(), tc.wantLog, "log substring for %s", tc.name)
			}
		})
	}
}

// TestValidatePSKBindingInputs_GossipDoesNotRefusePSK is the DoS-hardening
// regression guard. A compromised peer (or a compromised lighthouse
// forwarding gossip) MUST NOT be able to refuse a PSK by gossiping a
// hash that disagrees with the peer's own CA-signed cert. The cert is
// the trust anchor; gossip is diagnostic-only. We assert this for
// enforce mode (where the prior behaviour was to refuse) under both
// the rpinfo-absent and rpinfo-matches-cert sub-cases.
func TestValidatePSKBindingInputs_GossipDoesNotRefusePSK(t *testing.T) {
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)

	t.Run("enforce_cert_gossip_mismatch_rpinfo_match_uses_PSK", func(t *testing.T) {
		// The keystone case: cert + rpinfo both agree (operator has
		// done the right thing and the CA confirms it). The peer is
		// lying via gossip but the lie does not get to refuse the PSK.
		logger, buf := captureLogger()
		ok := ValidatePSKBindingInputs(PqPskBindingEnforce, BindingInputs{
			CertHash:        hashA,
			GossipedHash:    hashB,
			LocalProviderHash: hashA,
		}, logger)
		assert.True(t, ok, "cert+rpinfo agree; gossip disagreement must not refuse the PSK")
		assert.Contains(t, buf.String(), "ignoring gossip; cert is authoritative",
			"the lie must be visible to operators as a Warn-level log")
		assert.NotContains(t, buf.String(), "ERROR",
			"a peer lying via gossip is not an Error event — cert is the anchor")
	})

	t.Run("enforce_cert_gossip_mismatch_rpinfo_absent_refuses_on_rpinfo_not_gossip", func(t *testing.T) {
		// Here we still refuse, but the reason is "no rpinfo present"
		// (operator-controlled), not "gossip disagrees with cert". The
		// distinction matters: a compromised peer can fabricate gossip
		// but cannot make the operator drop the .rpinfo sidecar, so the
		// refusal cause is purely operator state.
		logger, buf := captureLogger()
		ok := ValidatePSKBindingInputs(PqPskBindingEnforce, BindingInputs{
			CertHash:     hashA,
			GossipedHash: hashB,
			// LocalProviderHash intentionally empty
		}, logger)
		assert.False(t, ok, "no rpinfo + enforce mode still refuses")
		assert.Contains(t, buf.String(), "refusing PSK; peer cert claims PQ-PSK binding but no provider binding hint present",
			"refusal reason must be rpinfo-absent, not cert/gossip-disagree")
		assert.Contains(t, buf.String(), "ignoring gossip; cert is authoritative",
			"the gossip lie is still surfaced as a Warn")
	})
}

// TestValidatePSKBinding_BackcompatWrapper verifies the legacy two-source
// entry point still produces identical decisions and identical log
// messages as it did before BindingInputs was introduced. Regression
// guard for the wrapper.
func TestValidatePSKBinding_BackcompatWrapper(t *testing.T) {
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)

	// Sample three pivotal cases the old TestValidatePSKBinding_AllCases
	// already covers, but route them through the new InputsX form via
	// the wrapper to assert behavioural parity.
	peerCertA := &stubCert{rpHash: mustHashBytes(t, hashA)}

	// warn + cert + rpinfo mismatch should produce "rosenpass binding
	// mismatch" (same message string as before the BindingInputs split).
	logger, buf := captureLogger()
	assert.True(t, ValidatePSKBinding(PqPskBindingWarn, peerCertA, hashB, logger))
	assert.Contains(t, buf.String(), "PQ-PSK binding mismatch")
	assert.NotContains(t, buf.String(), "cert/gossip", "wrapper must not invent a gossip claim")

	// enforce + cert only: refuse with the existing log message.
	logger, buf = captureLogger()
	assert.False(t, ValidatePSKBinding(PqPskBindingEnforce, peerCertA, "", logger))
	assert.Contains(t, buf.String(), "refusing PSK; peer cert claims PQ-PSK binding but no provider binding hint present")
}
