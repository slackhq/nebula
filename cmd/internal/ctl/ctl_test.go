package ctl

import (
	"encoding/json"
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

// TestParseCommandReportsWhatFlagSaid covers the three ways a flag line goes wrong, which
// are different mistakes: an unknown flag, a valid flag with a missing value, and a
// valid flag with a value it cannot parse.
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
			require.ErrorContains(t, err, "nebula: change-remote: "+tc.want)
			require.ErrorContains(t, err, "see 'nebula ctl change-remote -h'")
			assert.NotContains(t, err.Error(), "does not take")
		})
	}
}

// TestParseCommandOffPresentationFlagIsNoPreference: the daemon treats -json=false as
// no preference, so nebula ctl must too, or the same line renders differently on the
// two surfaces. Only a true value asks for JSON, and -pretty implies it.
func TestParseCommandOffPresentationFlagIsNoPreference(t *testing.T) {
	schema := []commands.CommandSchema{{
		Name: "device-info",
		Flags: []commands.FlagSchema{
			{Name: commands.FlagJSON, Bool: true, Default: "false"},
			{Name: commands.FlagPretty, Bool: true, Default: "false"},
		},
	}}

	for _, tc := range []struct {
		argv []string
		want commands.Format
		wire string
	}{
		{[]string{"device-info"}, commands.FormatUnset, "text"},
		{[]string{"device-info", "-json=false"}, commands.FormatUnset, "text"},
		{[]string{"device-info", "-json"}, commands.FormatJSON, "json"},
		{[]string{"device-info", "-pretty"}, commands.FormatPrettyJSON, "json"},
	} {
		t.Run(strings.Join(tc.argv[1:], " "), func(t *testing.T) {
			req, printedHelp, err := parseCommand(schema, tc.argv)
			require.NoError(t, err)
			assert.False(t, printedHelp)
			assert.Equal(t, tc.want, req.Format)
			assert.Equal(t, tc.wire, wireFormat(req.Format))
			assert.Nil(t, req.Params, "presentation flags are never sent as parameters")
		})
	}
}

// TestParseCommandReadsTheLineAsTheDaemonDoes: nebula ctl parses the line with the same
// rules as the daemon, so an operand after "--" reaches the command on both and a
// negative number before it is the flag it would be at an ssh prompt.
func TestParseCommandReadsTheLineAsTheDaemonDoes(t *testing.T) {
	schema := []commands.CommandSchema{{Name: "set"}}

	req, printedHelp, err := parseCommand(schema, []string{"set", "--", "-1"})
	require.NoError(t, err)
	assert.False(t, printedHelp)
	assert.Equal(t, commands.Name("set"), req.name)
	assert.Nil(t, req.Params)
	assert.Equal(t, []string{"-1"}, req.Args)

	_, _, err = parseCommand(schema, []string{"set", "-1"})
	require.ErrorContains(t, err, "flag provided but not defined: -1")
}

// TestOutputRendersForTheFormatAsked: what the daemon answered is read by the format the
// line asked for, never by sniffing the bytes. A text answer is the command's rendering,
// printed as it came; a JSON answer whose value is a string stays quoted, since to the
// script reading it that string is the JSON.
func TestOutputRendersForTheFormatAsked(t *testing.T) {
	text := &localapi.Response{Text: []byte("Log level is: info\n")}
	assert.Equal(t, "Log level is: info\n", output(text, commands.FormatUnset))
	assert.Equal(t, "Log level is: info\n", output(text, commands.FormatText))

	str := &localapi.Response{Result: json.RawMessage(`"some string"`)}
	assert.Equal(t, `"some string"`, output(str, commands.FormatJSON))
	assert.Equal(t, `"some string"`, output(str, commands.FormatPrettyJSON))

	// Keys stay in the order the daemon wrote them and a uint64 past 2^53 is not rounded,
	// which decoding into `any` and encoding again would do.
	obj := &localapi.Response{Result: json.RawMessage(`{"z":18446744073709551615,"a":{"y":[1,2],"b":true}}`)}
	//nolint:testifylint // the layout is what is under test, which JSONEq would not see
	assert.Equal(t, `{"z":18446744073709551615,"a":{"y":[1,2],"b":true}}`, output(obj, commands.FormatJSON))
	//nolint:testifylint // as above
	assert.Equal(t, "{\n    \"z\": 18446744073709551615,\n    \"a\": {\n        \"y\": [\n            1,\n            2\n        ],\n        \"b\": true\n    }\n}", output(obj, commands.FormatPrettyJSON))

	bad := &localapi.Response{Result: json.RawMessage(`{"a":`)}
	assert.Equal(t, `{"a":`, output(bad, commands.FormatPrettyJSON), "what cannot be indented is printed as it came")

	none := &localapi.Response{}
	assert.Empty(t, output(none, commands.FormatJSON))
	assert.Empty(t, output(none, commands.FormatUnset))
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
