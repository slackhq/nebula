package ctl

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/localapi"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveSocketReportsAnUnreadableConfig: an operator who named a config must hear
// that it could not be read, rather than have the command steered anywhere else.
func TestResolveSocketReportsAnUnreadableConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "typo.yml")

	_, _, _, err := resolveSocket("", missing)
	require.Error(t, err)
	assert.Contains(t, err.Error(), missing)
}

// TestResolveSocketTrustsANamedConfig: a config the operator named yields the socket it
// implies even when nothing is listening there, so a dial failure names that socket.
func TestResolveSocketTrustsANamedConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("local_api:\n  control:\n    socket: /nowhere/ctl.sock\n"), 0600))

	p, _, _, err := resolveSocket("", cfg)
	require.NoError(t, err)
	assert.Equal(t, "/nowhere/ctl.sock", p)
}

// TestResolveSocketDerivesWithoutSearching: with no override the path is the one the
// daemon would derive from the same config, computed rather than looked for.
func TestResolveSocketDerivesWithoutSearching(t *testing.T) {
	// A short private directory: the derived path has to fit sun_path and must not land
	// under /tmp, which is where an unset TMPDIR would put it on linux.
	base := test.ShortTempDir(t)
	t.Setenv("TMPDIR", base)

	cfg := filepath.Join(base, "config.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("static_host_map: {}\n"), 0600))

	want, err := localapi.DefaultSocketPath(cfg)
	require.NoError(t, err)

	p, _, _, err := resolveSocket("", cfg)
	require.NoError(t, err)
	assert.Equal(t, want, p)
}

func TestResolveSocketFlagWins(t *testing.T) {
	p, _, overrideIn, err := resolveSocket("/explicit.sock", "/does/not/matter.yml")
	require.NoError(t, err)
	assert.Equal(t, "/explicit.sock", p)
	assert.Empty(t, overrideIn)
}

// TestResolveSocketSaysWhenTheConfigNamedThePath: a path read from the override key is
// reported with the file it came from, so a dial failure can say that a daemon which
// has not reloaded since the key changed is still on the old path. A derived path is
// not an override.
func TestResolveSocketSaysWhenTheConfigNamedThePath(t *testing.T) {
	base := test.ShortTempDir(t)
	t.Setenv("TMPDIR", base)

	named := filepath.Join(base, "named.yml")
	require.NoError(t, os.WriteFile(named, []byte("local_api:\n  control:\n    socket: /nowhere/ctl.sock\n"), 0600))
	_, _, overrideIn, err := resolveSocket("", named)
	require.NoError(t, err)
	assert.Equal(t, named, overrideIn)

	derived := filepath.Join(base, "derived.yml")
	require.NoError(t, os.WriteFile(derived, []byte("static_host_map: {}\n"), 0600))
	_, _, overrideIn, err = resolveSocket("", derived)
	require.NoError(t, err)
	assert.Empty(t, overrideIn)
}

// TestParseCommandReportsWhatFlagSaid covers the three ways a flag line goes wrong. They
// are different mistakes, and the old blanket "does not take" was wrong for two of them:
// a valid flag with a missing value, and a valid flag with a value it cannot parse.
func TestParseCommandReportsWhatFlagSaid(t *testing.T) {
	schema := []commands.CommandSchema{{
		Name: "change-remote",
		Flags: []commands.FlagSchema{
			{Name: "address"},
			{Name: "by-index", Bool: true},
		},
	}}

	cases := map[string]struct {
		argv []string
		want string
	}{
		"missing value": {[]string{"change-remote", "-address"}, "flag needs an argument: -address"},
		"bad bool":      {[]string{"change-remote", "-by-index=maybe"}, "invalid boolean value \"maybe\" for -by-index"},
		"unknown flag":  {[]string{"change-remote", "-nope"}, "flag provided but not defined: -nope"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseCommand(schema, tc.argv)
			require.Error(t, err)
			assert.ErrorContains(t, err, "nebula: change-remote: "+tc.want)
			assert.ErrorContains(t, err, "see 'nebula ctl change-remote -h'")
			assert.NotContains(t, err.Error(), "does not take")
		})
	}
}

// TestSplitLineLiftsOwnFlagsFromAnywhere: -config and -socket are the client's wherever
// they appear, before the command or after it, in either spelling, so the two orders
// mean the same line. Everything else after the command word stays in order for the
// command's own parse, including flags and operands that happen to look like values.
func TestSplitLineLiftsOwnFlagsFromAnywhere(t *testing.T) {
	newFS := func() *flag.FlagSet {
		fs := flag.NewFlagSet("nebula ctl", flag.ContinueOnError)
		fs.String("config", "", "")
		fs.String("socket", "", "")
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
