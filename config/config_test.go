package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestConfig_Load(t *testing.T) {
	l := test.NewLogger()
	dir, err := os.MkdirTemp("", "config-test")
	// invalid yaml
	c := NewC(l)
	os.WriteFile(filepath.Join(dir, "01.yaml"), []byte(" invalid yaml"), 0644)
	require.EqualError(t, c.Load(dir), "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `invalid...` into map[string]interface {}")

	// simple multi config merge
	c = NewC(l)
	os.RemoveAll(dir)
	os.Mkdir(dir, 0755)

	require.NoError(t, err)

	os.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: hi"), 0644)
	os.WriteFile(filepath.Join(dir, "02.yml"), []byte("outer:\n  inner: override\nnew: hi"), 0644)
	require.NoError(t, c.Load(dir))
	expected := map[string]any{
		"outer": map[string]any{
			"inner": "override",
		},
		"new": "hi",
	}
	assert.Equal(t, expected, c.Settings)
}

// TestConfig_Resolve_AddFileErrorPropagates exercises the previously-
// swallowed addFile error path inside (*C).resolve. With a real
// filesystem we cannot easily make filepath.Abs error (it only fails
// when os.Getwd does, which requires deleted-cwd manipulation that is
// platform-fragile), so we follow the same pattern as
// cmd/nebula-cert/stdio.go's stdinReader: swap the package-level
// filepathAbs func for one that always returns an error.
//
// Cannot run with t.Parallel() — mutates the package-level
// filepathAbs var.
func TestConfig_Resolve_AddFileErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "x.yml")
	require.NoError(t, os.WriteFile(target, []byte("k: v\n"), 0o644))

	injected := errors.New("injected filepath.Abs failure")
	origAbs := filepathAbs
	t.Cleanup(func() { filepathAbs = origAbs })
	filepathAbs = func(string) (string, error) { return "", injected }

	c := NewC(test.NewLogger())
	err := c.Load(target)

	require.Error(t, err, "addFile error must propagate from resolve via Load")
	require.ErrorIs(t, err, injected,
		"propagated error must wrap the underlying cause so callers can errors.Is")
}

func TestConfig_Get(t *testing.T) {
	l := test.NewLogger()
	// test simple type
	c := NewC(l)
	c.Settings["firewall"] = map[string]any{"outbound": "hi"}
	assert.Equal(t, "hi", c.Get("firewall.outbound"))

	// test complex type
	inner := []map[string]any{{"port": "1", "code": "2"}}
	c.Settings["firewall"] = map[string]any{"outbound": inner}
	assert.EqualValues(t, inner, c.Get("firewall.outbound"))

	// test missing
	assert.Nil(t, c.Get("firewall.nope"))
}

func TestConfig_GetStringSlice(t *testing.T) {
	l := test.NewLogger()
	c := NewC(l)
	c.Settings["slice"] = []any{"one", "two"}
	assert.Equal(t, []string{"one", "two"}, c.GetStringSlice("slice", []string{}))
}

func TestConfig_GetBool(t *testing.T) {
	l := test.NewLogger()
	c := NewC(l)
	c.Settings["bool"] = true
	assert.True(t, c.GetBool("bool", false))

	c.Settings["bool"] = "true"
	assert.True(t, c.GetBool("bool", false))

	c.Settings["bool"] = false
	assert.False(t, c.GetBool("bool", true))

	c.Settings["bool"] = "false"
	assert.False(t, c.GetBool("bool", true))

	c.Settings["bool"] = "Y"
	assert.True(t, c.GetBool("bool", false))

	c.Settings["bool"] = "yEs"
	assert.True(t, c.GetBool("bool", false))

	c.Settings["bool"] = "N"
	assert.False(t, c.GetBool("bool", true))

	c.Settings["bool"] = "nO"
	assert.False(t, c.GetBool("bool", true))
}

func TestConfig_HasChanged(t *testing.T) {
	l := test.NewLogger()
	// No reload has occurred, return false
	c := NewC(l)
	c.Settings["test"] = "hi"
	assert.False(t, c.HasChanged(""))

	// Test key change
	c = NewC(l)
	c.Settings["test"] = "hi"
	c.oldSettings = map[string]any{"test": "no"}
	assert.True(t, c.HasChanged("test"))
	assert.True(t, c.HasChanged(""))

	// No key change
	c = NewC(l)
	c.Settings["test"] = "hi"
	c.oldSettings = map[string]any{"test": "hi"}
	assert.False(t, c.HasChanged("test"))
	assert.False(t, c.HasChanged(""))
}

func TestConfig_ReloadConfig(t *testing.T) {
	l := test.NewLogger()
	done := make(chan bool, 1)
	dir, err := os.MkdirTemp("", "config-test")
	require.NoError(t, err)
	os.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: hi"), 0644)

	c := NewC(l)
	require.NoError(t, c.Load(dir))

	assert.False(t, c.HasChanged("outer.inner"))
	assert.False(t, c.HasChanged("outer"))
	assert.False(t, c.HasChanged(""))

	os.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: ho"), 0644)

	c.RegisterReloadCallback(func(c *C) {
		done <- true
	})

	c.ReloadConfig()
	assert.True(t, c.HasChanged("outer.inner"))
	assert.True(t, c.HasChanged("outer"))
	assert.True(t, c.HasChanged(""))

	// Make sure we call the callbacks
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		panic("timeout")
	}

}

// Ensure mergo merges are done the way we expect.
// This is needed to test for potential regressions, like:
// - https://github.com/imdario/mergo/issues/187
func TestConfig_MergoMerge(t *testing.T) {
	configs := [][]byte{
		[]byte(`
listen:
  port: 1234
`),
		[]byte(`
firewall:
  inbound:
    - port: 443
      proto: tcp
      groups:
        - server
    - port: 443
      proto: tcp
      groups:
        - webapp
`),
		[]byte(`
listen:
  host: 0.0.0.0
  port: 4242
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: icmp
      host: any
`),
	}

	var m map[string]any

	// merge the same way config.parse() merges
	for _, b := range configs {
		var nm map[string]any
		err := yaml.Unmarshal(b, &nm)
		require.NoError(t, err)

		// We need to use WithAppendSlice so that firewall rules in separate
		// files are appended together
		err = mergo.Merge(&nm, m, mergo.WithAppendSlice)
		m = nm
		require.NoError(t, err)
	}

	t.Logf("Merged Config: %#v", m)
	mYaml, err := yaml.Marshal(m)
	require.NoError(t, err)
	t.Logf("Merged Config as YAML:\n%s", mYaml)

	// If a bug is present, some items might be replaced instead of merged like we expect
	expected := map[string]any{
		"firewall": map[string]any{
			"inbound": []any{
				map[string]any{"host": "any", "port": "any", "proto": "icmp"},
				map[string]any{"groups": []any{"server"}, "port": 443, "proto": "tcp"},
				map[string]any{"groups": []any{"webapp"}, "port": 443, "proto": "tcp"}},
			"outbound": []any{
				map[string]any{"host": "any", "port": "any", "proto": "any"}}},
		"listen": map[string]any{
			"host": "0.0.0.0",
			"port": 4242,
		},
	}
	assert.Equal(t, expected, m)
}
