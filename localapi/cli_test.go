package localapi

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCommandLineReportsWhatFlagSaid covers the three ways a flag line goes wrong, which
// are different mistakes: an unknown flag, a valid flag with a missing value, and a
// valid flag with a value it cannot parse.
func TestParseCommandLineReportsWhatFlagSaid(t *testing.T) {
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
			_, _, err := ParseCommandLine(schema, tc.argv, "nebula ctl", io.Discard)
			require.Error(t, err)
			require.ErrorContains(t, err, "change-remote: "+tc.want)
			require.ErrorContains(t, err, "see 'nebula ctl change-remote -h'")
			assert.NotContains(t, err.Error(), "does not take")
		})
	}
}

// TestParseCommandLineOffPresentationFlagIsNoPreference: the daemon treats -json=false as
// no preference, so nebula ctl must too, or the same line renders differently on the
// two surfaces. Only a true value asks for JSON, and -pretty implies it.
func TestParseCommandLineOffPresentationFlagIsNoPreference(t *testing.T) {
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
			req, printedHelp, err := ParseCommandLine(schema, tc.argv, "nebula ctl", io.Discard)
			require.NoError(t, err)
			assert.False(t, printedHelp)
			assert.Equal(t, tc.want, req.Format)
			assert.Equal(t, tc.wire, WireFormat(req.Format))
			assert.Nil(t, req.Params, "presentation flags are never sent as parameters")
		})
	}
}

// TestParseCommandLineReadsTheLineAsTheDaemonDoes: nebula ctl parses the line with the same
// rules as the daemon, so an operand after "--" reaches the command on both and a
// negative number before it is the flag it would be at an ssh prompt.
func TestParseCommandLineReadsTheLineAsTheDaemonDoes(t *testing.T) {
	schema := []commands.CommandSchema{{Name: "set"}}

	req, printedHelp, err := ParseCommandLine(schema, []string{"set", "--", "-1"}, "nebula ctl", io.Discard)
	require.NoError(t, err)
	assert.False(t, printedHelp)
	assert.Equal(t, commands.Name("set"), req.Name)
	assert.Nil(t, req.Params)
	assert.Equal(t, []string{"-1"}, req.Args)

	_, _, err = ParseCommandLine(schema, []string{"set", "-1"}, "nebula ctl", io.Discard)
	require.ErrorContains(t, err, "flag provided but not defined: -1")
}

// TestRenderForTheFormatAsked: what the daemon answered is read by the format the
// line asked for, never by sniffing the bytes. A text answer is the command's rendering,
// printed as it came; a JSON answer whose value is a string stays quoted, since to the
// script reading it that string is the JSON.
func TestRenderForTheFormatAsked(t *testing.T) {
	text := &Response{Text: []byte("Log level is: info\n")}
	assert.Equal(t, "Log level is: info\n", text.Render(commands.FormatUnset))
	assert.Equal(t, "Log level is: info\n", text.Render(commands.FormatText))

	str := &Response{Result: json.RawMessage(`"some string"`)}
	assert.Equal(t, `"some string"`, str.Render(commands.FormatJSON))
	assert.Equal(t, `"some string"`, str.Render(commands.FormatPrettyJSON))

	// Keys stay in the order the daemon wrote them and a uint64 past 2^53 is not rounded,
	// which decoding into `any` and encoding again would do.
	obj := &Response{Result: json.RawMessage(`{"z":18446744073709551615,"a":{"y":[1,2],"b":true}}`)}
	//nolint:testifylint // the layout is what is under test, which JSONEq would not see
	assert.Equal(t, `{"z":18446744073709551615,"a":{"y":[1,2],"b":true}}`, obj.Render(commands.FormatJSON))
	//nolint:testifylint // as above
	assert.Equal(t, "{\n    \"z\": 18446744073709551615,\n    \"a\": {\n        \"y\": [\n            1,\n            2\n        ],\n        \"b\": true\n    }\n}", obj.Render(commands.FormatPrettyJSON))

	bad := &Response{Result: json.RawMessage(`{"a":`)}
	assert.Equal(t, `{"a":`, bad.Render(commands.FormatPrettyJSON), "what cannot be indented is printed as it came")

	none := &Response{}
	assert.Empty(t, none.Render(commands.FormatJSON))
	assert.Empty(t, none.Render(commands.FormatUnset))
}

// TestSplitCommandLineLiftsOwnFlagsFromAnywhere: -config and -socket are the client's wherever
// they appear, before the command or after it, in either spelling, so the two orders
// mean the same line. Everything else after the command word stays in order for the
// command's own parse, including flags and operands that happen to look like values.
func TestSplitCommandLineLiftsOwnFlagsFromAnywhere(t *testing.T) {
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
			own, cmd := SplitCommandLine(newFS(), tc.args)
			assert.Equal(t, tc.wantOwn, own)
			assert.Equal(t, tc.wantCmd, cmd)
		})
	}
}

// TestParseCommandLinePointsAtTheClientsHelp: a parse error names the client the
// operator typed, so a program embedding the client sends them to a line that works,
// and a command's -h is written where the caller asked.
func TestParseCommandLinePointsAtTheClientsHelp(t *testing.T) {
	schema := []commands.CommandSchema{{Name: "change-remote"}}

	_, _, err := ParseCommandLine(schema, []string{"change-remote", "-nope"}, "dnclient ctl", io.Discard)
	require.ErrorContains(t, err, "see 'dnclient ctl change-remote -h'")

	var help bytes.Buffer
	_, printedHelp, err := ParseCommandLine(schema, []string{"change-remote", "-h"}, "dnclient ctl", &help)
	require.NoError(t, err)
	assert.True(t, printedHelp)
	assert.Contains(t, help.String(), "change-remote")
}
