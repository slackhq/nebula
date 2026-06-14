package pq

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These integration tests wire the real FileProvider together with
// ValidatePSKBinding and walk the full decision tree against on-disk
// inputs — not mocks. The load-bearing case is
// TestRPBinding_BackwardsCompat_NoFiles_NoExt, which proves that an
// operator running with .psk files only (no .rpinfo, no cert
// extension) sees identical behaviour in every mode after the gap-2
// validation wrapper was wired in.

// writePSK drops a 32-byte PSK at "<sha256(pub)>.psk" inside dir, and
// returns the matching peer static pubkey bytes plus the stem string
// (lowercase hex) callers can use to derive companion file names.
func writePSK(t *testing.T, dir string, label byte, psk []byte) (pub []byte, stem string) {
	t.Helper()
	pub = make([]byte, 32)
	for i := range pub {
		pub[i] = label
	}
	sum := sha256.Sum256(pub)
	stem = hex.EncodeToString(sum[:])
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".psk"), psk, 0o600))
	return pub, stem
}

// writeRPInfo drops a "<stem>.rpinfo" companion containing the given
// 64-char hex hash and a trailing newline.
func writeRPInfo(t *testing.T, dir, stem, hexHash string) {
	t.Helper()
	require.Len(t, hexHash, 64, "rpinfo hash must be 64 hex chars")
	require.NoError(t, os.WriteFile(filepath.Join(dir, stem+".rpinfo"), []byte(hexHash+"\n"), 0o600))
}

// TestRPBinding_BackwardsCompat_NoFiles_NoExt is the bw-compat
// regression guard for gap 3. It pins down the operator-default state
// — a directory of .psk files only (no .rpinfo companions) and a peer
// presenting either a v1 cert or a v2 cert without the
// rosenpassPubKeySha256 extension — and asserts that every
// rp_binding.mode returns the PSK. This is the contract that lets the
// gap-2 wrapper ship in "warn" mode by default without disturbing any
// existing deployment.
func TestRPBinding_BackwardsCompat_NoFiles_NoExt(t *testing.T) {
	dir := t.TempDir()
	pskBytes := bytes32(0x11)
	pub, _ := writePSK(t, dir, 0xAA, pskBytes)

	// FileProvider runs the initial scan in NewFileProvider, so files
	// dropped before the constructor are picked up synchronously. This
	// keeps the test independent of the fsnotify debounce window.
	p2, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p2.Close() })

	require.Equal(t, pskBytes, p2.Lookup(pub), "psk must load from real FileProvider")
	require.Equal(t, "", p2.LookupRPHash(pub), "no .rpinfo file => empty rpHash")

	// Walk every mode with both a nil cert (pre-cert-cache initiator
	// path) and a v2-shaped cert that simply lacks the extension. The
	// gap-2 wrapper must treat both identically.
	noExt := &stubCert{rpHash: nil}
	for _, mode := range []PqPskBindingMode{PqPskBindingOff, PqPskBindingWarn, PqPskBindingEnforce} {
		t.Run(mode.String()+"_nil_cert", func(t *testing.T) {
			rpHash := p2.LookupRPHash(pub)
			ok := ValidatePSKBinding(mode, nil, rpHash, slog.Default())
			assert.True(t, ok, "mode=%s + no extension + no rpinfo must use PSK", mode)
		})
		t.Run(mode.String()+"_v2_cert_no_ext", func(t *testing.T) {
			rpHash := p2.LookupRPHash(pub)
			ok := ValidatePSKBinding(mode, noExt, rpHash, slog.Default())
			assert.True(t, ok, "mode=%s + cert without ext + no rpinfo must use PSK", mode)
		})
	}
}

// TestRPBinding_Integration_FileProviderHappyPath wires a matching
// .rpinfo file next to a .psk and asserts that all three modes accept
// the PSK when the cert extension and rpinfo agree. Confirms the
// "fully-bound deployment" steady state at the FileProvider seam.
func TestRPBinding_Integration_FileProviderHappyPath(t *testing.T) {
	dir := t.TempDir()
	psk := bytes32(0x22)
	pub, stem := writePSK(t, dir, 0xBB, psk)

	rpHashHex := strings.Repeat("ab", 32)
	writeRPInfo(t, dir, stem, rpHashHex)

	p, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	require.Equal(t, psk, p.Lookup(pub))
	require.Equal(t, rpHashHex, p.LookupRPHash(pub))

	peerCert := &stubCert{rpHash: mustHashBytes(t, rpHashHex)}
	for _, mode := range []PqPskBindingMode{PqPskBindingOff, PqPskBindingWarn, PqPskBindingEnforce} {
		t.Run(mode.String(), func(t *testing.T) {
			ok := ValidatePSKBinding(mode, peerCert, p.LookupRPHash(pub), slog.Default())
			assert.True(t, ok, "mode=%s + matching cert ext + matching rpinfo must use PSK", mode)
		})
	}
}

// TestRPBinding_Integration_FileProviderExtNoRPInfo covers the
// "operator deployed certs with the extension but hasn't rolled out
// .rpinfo files yet" state. off/warn must still use the PSK; enforce
// must refuse it. This is the regression that flips when an operator
// graduates from warn to enforce too early.
func TestRPBinding_Integration_FileProviderExtNoRPInfo(t *testing.T) {
	dir := t.TempDir()
	psk := bytes32(0x33)
	pub, _ := writePSK(t, dir, 0xCC, psk)

	p, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	require.Equal(t, psk, p.Lookup(pub))
	require.Equal(t, "", p.LookupRPHash(pub), "no .rpinfo => empty rpHash")

	rpHashHex := strings.Repeat("cd", 32)
	peerCert := &stubCert{rpHash: mustHashBytes(t, rpHashHex)}

	logger, buf := captureLogger()
	assert.True(t, ValidatePSKBinding(PqPskBindingOff, peerCert, p.LookupRPHash(pub), logger),
		"off must use the PSK even when cert claims a binding")
	assert.Empty(t, buf.String(), "off mode must not log anything")

	logger, buf = captureLogger()
	assert.True(t, ValidatePSKBinding(PqPskBindingWarn, peerCert, p.LookupRPHash(pub), logger),
		"warn must use the PSK and log")
	assert.Contains(t, buf.String(), "peer cert claims PQ-PSK binding but no provider binding hint present")

	logger, buf = captureLogger()
	assert.False(t, ValidatePSKBinding(PqPskBindingEnforce, peerCert, p.LookupRPHash(pub), logger),
		"enforce must refuse the PSK when cert claim is unverified")
	assert.Contains(t, buf.String(), "refusing PSK; peer cert claims PQ-PSK binding but no provider binding hint present")
}

// TestRPBinding_Integration_FileProviderMismatch wires a .rpinfo file
// whose contents disagree with the cert extension, mirroring a
// re-keyed sidecar. off/warn keep using the PSK (with a Warn log);
// enforce refuses.
func TestRPBinding_Integration_FileProviderMismatch(t *testing.T) {
	dir := t.TempDir()
	psk := bytes32(0x44)
	pub, stem := writePSK(t, dir, 0xDD, psk)

	rpinfoHash := strings.Repeat("11", 32)
	certHash := strings.Repeat("22", 32)
	writeRPInfo(t, dir, stem, rpinfoHash)

	p, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	require.Equal(t, rpinfoHash, p.LookupRPHash(pub))

	peerCert := &stubCert{rpHash: mustHashBytes(t, certHash)}

	logger, buf := captureLogger()
	assert.True(t, ValidatePSKBinding(PqPskBindingOff, peerCert, p.LookupRPHash(pub), logger),
		"off must use PSK regardless of mismatch")
	assert.Empty(t, buf.String(), "off must be silent")

	logger, buf = captureLogger()
	assert.True(t, ValidatePSKBinding(PqPskBindingWarn, peerCert, p.LookupRPHash(pub), logger),
		"warn must use PSK and Warn-log the mismatch")
	assert.Contains(t, buf.String(), "PQ-PSK binding mismatch")

	logger, buf = captureLogger()
	assert.False(t, ValidatePSKBinding(PqPskBindingEnforce, peerCert, p.LookupRPHash(pub), logger),
		"enforce must refuse PSK on mismatch")
	assert.Contains(t, buf.String(), "refusing PSK; PQ-PSK binding mismatch")
}

// TestRPBinding_Integration_FileProviderRPInfoNoCertExt covers the
// "operator dropped .rpinfo for a peer whose CA hasn't been upgraded
// yet" state. The PSK is always used (no cert claim to verify
// against), but warn/enforce surface an Info log so the operator knows
// they've staged ahead of the CA rollout.
func TestRPBinding_Integration_FileProviderRPInfoNoCertExt(t *testing.T) {
	dir := t.TempDir()
	psk := bytes32(0x55)
	pub, stem := writePSK(t, dir, 0xEE, psk)

	rpHashHex := strings.Repeat("ef", 32)
	writeRPInfo(t, dir, stem, rpHashHex)

	p, err := NewFileProvider(dir, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	require.Equal(t, rpHashHex, p.LookupRPHash(pub))

	// nil cert (initiator with no cached peer cert) and a v2 cert
	// without the extension should behave the same way. cert.Certificate
	// is an interface, so the table uses a concrete-cert builder to
	// avoid the typed-nil-interface foot-gun.
	cases := []struct {
		name string
		cert cert.Certificate
	}{
		{"nil_cert", nil},
		{"v2_no_ext", &stubCert{rpHash: nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []PqPskBindingMode{PqPskBindingOff, PqPskBindingWarn, PqPskBindingEnforce} {
				t.Run(mode.String(), func(t *testing.T) {
					ok := ValidatePSKBinding(mode, tc.cert, p.LookupRPHash(pub), slog.Default())
					assert.True(t, ok,
						"rpinfo present + no cert claim must always use PSK (mode=%s)", mode)
				})
			}
		})
	}
}

// TestRPBinding_Integration_DefaultModeIsWarn pins the
// ParsePqPskBindingMode contract that an empty/unset config string maps
// to warn. This is the single line of code separating an upgrade from
// being silent (good) versus disruptive (bad), so it gets its own
// integration-level test that uses the parser the way pki.go does.
func TestRPBinding_Integration_DefaultModeIsWarn(t *testing.T) {
	// Operators who never set pq.rp_binding.mode in their config land
	// in this branch via config.GetString("pq.rp_binding.mode", "").
	got, err := ParsePqPskBindingMode("")
	require.NoError(t, err)
	require.Equal(t, PqPskBindingWarn, got,
		"empty config string must map to warn — the backwards-compat default")
}
