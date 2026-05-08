package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withStdin temporarily replaces stdinReader for the duration of t.
func withStdin(t *testing.T, r io.Reader) {
	t.Helper()
	prev := stdinReader
	stdinReader = r
	t.Cleanup(func() { stdinReader = prev })
}

func Test_readInput_stdin(t *testing.T) {
	withStdin(t, bytes.NewBufferString("hello"))
	var claims ioClaims

	got, err := readInput("path", "-", &claims)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)
	assert.Equal(t, "path", claims.in)
}

func Test_readInput_file(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(p, []byte("file"), 0600))
	var claims ioClaims

	got, err := readInput("path", p, &claims)
	require.NoError(t, err)
	assert.Equal(t, []byte("file"), got)
	assert.Equal(t, "", claims.in)
}

func Test_readInput_doubleStdinErrors(t *testing.T) {
	withStdin(t, bytes.NewBufferString("hello"))
	var claims ioClaims

	_, err := readInput("ca-key", "-", &claims)
	require.NoError(t, err)

	_, err = readInput("ca-crt", "-", &claims)
	require.EqualError(t, err, `-ca-key and -ca-crt both set to "-", only one input may read from stdin`)
}

func Test_openInput_stdin(t *testing.T) {
	withStdin(t, bytes.NewBufferString("hi"))
	var claims ioClaims

	r, err := openInput("ca", "-", &claims)
	require.NoError(t, err)
	defer r.Close()
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, []byte("hi"), b)
}

func Test_openInput_doubleStdinErrors(t *testing.T) {
	withStdin(t, bytes.NewBufferString("hi"))
	var claims ioClaims

	r, err := openInput("ca", "-", &claims)
	require.NoError(t, err)
	r.Close()

	_, err = openInput("crt", "-", &claims)
	require.EqualError(t, err, `-ca and -crt both set to "-", only one input may read from stdin`)
}

func Test_writeOutput_stdout(t *testing.T) {
	out := &bytes.Buffer{}

	err := writeOutput("-", []byte("payload"), 0600, out)
	require.NoError(t, err)
	assert.Equal(t, "payload", out.String())
}

func Test_writeOutput_file(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	out := &bytes.Buffer{}

	err := writeOutput(p, []byte("payload"), 0600, out)
	require.NoError(t, err)
	assert.Empty(t, out.String())
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, []byte("payload"), got)
}

func Test_reserveOutputs_noConflict(t *testing.T) {
	var claims ioClaims
	require.NoError(t, reserveOutputs(&claims,
		"out-key", "/tmp/key",
		"out-crt", "-",
		"out-qr", "",
	))
	assert.Equal(t, "out-crt", claims.out)
}

func Test_reserveOutputs_conflict(t *testing.T) {
	var claims ioClaims
	err := reserveOutputs(&claims,
		"out-key", "-",
		"out-crt", "-",
	)
	require.EqualError(t, err, `-out-key and -out-crt both set to "-", only one output may write to stdout`)
}

func Test_reserveOutputs_panicsOnOddPairs(t *testing.T) {
	defer func() {
		r := recover()
		require.NotNil(t, r)
	}()
	var claims ioClaims
	_ = reserveOutputs(&claims, "out-key")
}

func Test_reserveInputs_noConflict(t *testing.T) {
	var claims ioClaims
	require.NoError(t, reserveInputs(&claims,
		"ca-key", "/tmp/ca.key",
		"ca-crt", "-",
		"in-pub", "",
	))
	assert.Equal(t, "ca-crt", claims.in)
}

func Test_reserveInputs_conflict(t *testing.T) {
	var claims ioClaims
	err := reserveInputs(&claims,
		"ca-key", "-",
		"ca-crt", "-",
	)
	require.EqualError(t, err, `-ca-key and -ca-crt both set to "-", only one input may read from stdin`)
}

func Test_claimIn_idempotent(t *testing.T) {
	// pre-claim then a lazy re-claim of the same flag should be a no-op
	var claims ioClaims
	require.NoError(t, claims.claimIn("ca-key"))
	require.NoError(t, claims.claimIn("ca-key"))
	assert.Equal(t, "ca-key", claims.in)
}

func Test_claimOut_idempotent(t *testing.T) {
	var claims ioClaims
	require.NoError(t, claims.claimOut("out-crt"))
	require.NoError(t, claims.claimOut("out-crt"))
	assert.Equal(t, "out-crt", claims.out)
}

func Test_isStdio(t *testing.T) {
	assert.True(t, isStdio("-"))
	assert.False(t, isStdio(""))
	assert.False(t, isStdio("./-"))
	assert.False(t, isStdio("foo"))
}
