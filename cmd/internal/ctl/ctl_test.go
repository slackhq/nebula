package ctl

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/localapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveSocketReportsAnUnreadableConfig: an operator who named a config must hear
// that it could not be read, rather than have the command steered anywhere else.
func TestResolveSocketReportsAnUnreadableConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "typo.yml")

	_, err := resolveSocket("", missing)
	require.Error(t, err)
	assert.Contains(t, err.Error(), missing)
}

// TestResolveSocketGuessedConfigNeedNotBeReadable: a config nobody named is a guess, and
// one that cannot be read, a root daemon's config read by a member of the socket's
// group, means the default path rather than an error.
func TestResolveSocketGuessedConfigNeedNotBeReadable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "config.yml")

	p, err := socketFromConfigFile(missing, false)
	require.NoError(t, err)
	assert.Equal(t, localapi.DefaultSocketPath, p)

	_, err = socketFromConfigFile(missing, true)
	require.ErrorContains(t, err, missing)
}

// nowhereSocket is a socket name nothing listens on, spelled the way the platform
// requires: a full pipe name on windows, an absolute path elsewhere.
var nowhereSocket = map[bool]string{true: `\\.\pipe\nebula-nowhere`, false: "/nowhere/ctl.sock"}[runtime.GOOS == "windows"]

// namedSocketConfig is a config that names nowhereSocket as the control socket. Single
// quotes keep a pipe name's backslashes literal in YAML.
var namedSocketConfig = "local_api:\n  control:\n    socket: '" + nowhereSocket + "'\n"

// TestResolveSocketTrustsANamedConfig: a config the operator named yields the socket it
// implies even when nothing is listening there, so a dial failure names that socket.
func TestResolveSocketTrustsANamedConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(cfg, []byte(namedSocketConfig), 0600))

	p, err := resolveSocket("", cfg)
	require.NoError(t, err)
	assert.Equal(t, nowhereSocket, p)
}

// TestResolveSocketSaysTheSocketIsDisabled: a config that turns the control socket off
// is answered with that, not with a dial to a path nothing serves. -socket still wins.
func TestResolveSocketSaysTheSocketIsDisabled(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("local_api:\n  control:\n    enabled: false\n"), 0600))

	_, err := resolveSocket("", cfg)
	require.ErrorContains(t, err, "the control socket is disabled in "+cfg+" by local_api.control.enabled")

	p, err := resolveSocket("/explicit.sock", cfg)
	require.NoError(t, err)
	assert.Equal(t, "/explicit.sock", p)
}

// TestResolveSocketUsesTheDefaultWithoutAnOverride: a config that does not name the
// socket means the default path, the same one the daemon serves with that config, and
// no config at all means the default too, since that is where a daemon started without
// an override serves. Nothing is searched for.
func TestResolveSocketUsesTheDefaultWithoutAnOverride(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("static_host_map: {}\n"), 0600))

	p, err := resolveSocket("", cfg)
	require.NoError(t, err)
	assert.Equal(t, localapi.DefaultSocketPath, p)

	// The test binary has no config next to it.
	p, err = resolveSocket("", "")
	require.NoError(t, err)
	assert.Equal(t, localapi.DefaultSocketPath, p)
}

func TestResolveSocketFlagWins(t *testing.T) {
	p, err := resolveSocket("/explicit.sock", "/does/not/matter.yml")
	require.NoError(t, err)
	assert.Equal(t, "/explicit.sock", p)
}

// TestSplitLineLiftsOwnFlagsFromAnywhere: -config and -socket are the client's wherever
// they appear, before the command or after it, in either spelling, so the two orders
// mean the same line. Everything else after the command word stays in order for the
// command's own parse, including flags and operands that happen to look like values.
func TestSplitLineLiftsOwnFlagsFromAnywhere(t *testing.T) {
	newFS := func() *flag.FlagSet {
		fs := flag.NewFlagSet("nebula ctl", flag.ContinueOnError)
		fs.String(commands.FlagConfig, "", "")
		fs.String(commands.FlagSocket, "", "")
		return fs
	}

	for _, tc := range []struct {
		args    []string
		wantOwn []string
		wantCmd []string
	}{
		{nil, nil, nil},
		{[]string{"identity"}, nil, []string{"identity"}},
		{[]string{"-config", "x", "identity"}, []string{"-config", "x"}, []string{"identity"}},
		{[]string{"identity", "-config", "x"}, []string{"-config", "x"}, []string{"identity"}},
		{[]string{"identity", "-config=x"}, []string{"-config=x"}, []string{"identity"}},
		{[]string{"identity", "--socket", "s"}, []string{"--socket", "s"}, []string{"identity"}},
		{[]string{"-socket", "s", "identity", "-config", "x"}, []string{"-socket", "s", "-config", "x"}, []string{"identity"}},
		// The command's flags and operands are left where they are, around the lifted ones.
		{[]string{"print-tunnel", "10.0.0.1", "-config", "x", "-json"}, []string{"-config", "x"}, []string{"print-tunnel", "10.0.0.1", "-json"}},
		{[]string{"change-remote", "-address", "1.2.3.4:5", "-socket", "s", "10.0.0.1"}, []string{"-socket", "s"}, []string{"change-remote", "-address", "1.2.3.4:5", "10.0.0.1"}},
		// -h before the command is the client's usage; after it, the command's help.
		{[]string{"-h"}, []string{"-h"}, nil},
		{[]string{"identity", "-h"}, nil, []string{"identity", "-h"}},
		// An unknown flag before the command is the client's to report, and does not
		// swallow the command word as its value.
		{[]string{"-nope", "identity"}, []string{"-nope"}, []string{"identity"}},
		// A -config with nothing after it is left for fs.Parse to report.
		{[]string{"identity", "-config"}, []string{"-config"}, []string{"identity"}},
		// "--" before the command is consumed, as fs.Parse consumed it; after the command
		// it belongs to the line and ends the lifting.
		{[]string{"--", "identity", "-config", "x"}, []string{"-config", "x"}, []string{"identity"}},
		{[]string{"identity", "--", "-config", "x"}, nil, []string{"identity", "--", "-config", "x"}},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			own, cmd := splitLine(newFS(), tc.args)
			assert.Equal(t, tc.wantOwn, own)
			assert.Equal(t, tc.wantCmd, cmd)
		})
	}
}

// TestTrailingHandlesWordsAfterTheDaemonsFlags: what flag.Parse leaves behind is never
// a daemon to start. A leading ctl runs the client on the rest, with the daemon's
// -config carried over; anything else is a mistyped subcommand. Only -h is run here,
// since the client's help needs no daemon: it proves the words reach Run and that a
// carried -config is accepted by it.
func TestTrailingHandlesWordsAfterTheDaemonsFlags(t *testing.T) {
	code, done := Trailing(nil, "")
	assert.False(t, done)
	assert.Equal(t, 0, code)

	code, done = Trailing([]string{"clt"}, "")
	assert.True(t, done)
	assert.Equal(t, 1, code)

	code, done = Trailing([]string{Word, "-h"}, "")
	assert.True(t, done)
	assert.Equal(t, 0, code)

	code, done = Trailing([]string{Word, "-h"}, "/etc/nebula/config.yml")
	assert.True(t, done)
	assert.Equal(t, 0, code)
}

// TestSubcommandOnlyReadsTheFirstWord: a flag first means the line is the daemon's to
// parse, and whatever follows the flags is Trailing's to judge.
func TestSubcommandOnlyReadsTheFirstWord(t *testing.T) {
	_, done := Subcommand([]string{"nebula", "-config", "x", Word})
	assert.False(t, done)

	code, done := Subcommand([]string{"nebula", "clt"})
	assert.True(t, done)
	assert.Equal(t, 1, code)

	code, done = Subcommand([]string{"nebula", Word, "-h"})
	assert.True(t, done)
	assert.Equal(t, 0, code)
}
