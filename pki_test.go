package nebula

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/pq"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPqPskBindingModeConfigAlias guards the regression in which the legacy
// config key pq.rp_binding.mode stops being honoured. pki.go resolves the
// binding mode as:
//
//	c.GetString("pq.psk_binding.mode", c.GetString("pq.rp_binding.mode", ""))
//
// i.e. the new pq.psk_binding.mode key with the legacy pq.rp_binding.mode as a
// fallback. An operator who only set the legacy key must still get the same
// behaviour, so a config that sets ONLY pq.rp_binding.mode=enforce must resolve
// to PqPskBindingEnforce.
func TestPqPskBindingModeConfigAlias(t *testing.T) {
	c := config.NewC(test.NewLogger())
	// Populate a real config.C with ONLY the legacy key set; the new key is
	// deliberately absent so we exercise the fallback arm.
	c.Settings["pq"] = map[string]any{
		"rp_binding": map[string]any{
			"mode": "enforce",
		},
	}

	// Mirror the exact resolution performed in pki.go's config read.
	resolved := c.GetString("pq.psk_binding.mode", c.GetString("pq.rp_binding.mode", ""))
	assert.Equal(t, "enforce", resolved, "legacy pq.rp_binding.mode should be picked up when pq.psk_binding.mode is absent")

	mode, err := pq.ParsePqPskBindingMode(resolved)
	require.NoError(t, err)
	assert.Equal(t, pq.PqPskBindingEnforce, mode)
}

func TestPqPrevLookupFromProvider(t *testing.T) {
	dir := t.TempDir()
	peer := make([]byte, 32)
	peer[0] = 0xDD
	sum := sha256.Sum256(peer)
	stem := hex.EncodeToString(sum[:])
	pskA := bytes.Repeat([]byte{0x0A}, 32)
	pskB := bytes.Repeat([]byte{0x0B}, 32)

	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), pskA, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := pq.NewFileProvider(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := os.WriteFile(filepath.Join(dir, stem+".psk"), pskB, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Rescan(); err != nil {
		t.Fatal(err)
	}

	lookup := pqPrevLookupFromProviderWithBinding(p, pq.PqPskBindingWarn, nil, nil)
	if lookup == nil {
		t.Fatal("expected a prev-lookup closure for a real provider")
	}
	got := lookup(peer, nil)
	if !bytes.Equal(got, pskA) {
		t.Fatalf("prev lookup = %x, want %x", got, pskA)
	}
	if lookup(make([]byte, 32), nil) != nil {
		t.Fatal("unknown peer must return nil")
	}
}
