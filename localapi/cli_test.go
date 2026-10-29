package localapi

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCommandLineReportsWhatFlagSaid: unknown flag, missing value and bad value
// each get flag's own error.
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
			_, _, err := parseCommandLine(schema, tc.argv, "nebula ctl", io.Discard)
			require.Error(t, err)
			require.ErrorContains(t, err, "change-remote: "+tc.want)
			require.ErrorContains(t, err, "see 'nebula ctl change-remote -h'")
			assert.NotContains(t, err.Error(), "does not take")
		})
	}
}

// TestParseCommandLineOffPresentationFlagIsNoPreference: -json=false is no preference,
// matching the server; -pretty implies JSON.
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
			req, printedHelp, err := parseCommandLine(schema, tc.argv, "nebula ctl", io.Discard)
			require.NoError(t, err)
			assert.False(t, printedHelp)
			assert.Equal(t, tc.want, req.Format)
			assert.Equal(t, tc.wire, wireFormat(req.Format))
			assert.Nil(t, req.Params, "presentation flags are never sent as parameters")
		})
	}
}

// TestParseCommandLineReadsTheLineAsTheDaemonDoes: "--" ends flags, and a negative
// number before it is parsed as a flag, as over ssh.
func TestParseCommandLineReadsTheLineAsTheDaemonDoes(t *testing.T) {
	schema := []commands.CommandSchema{{Name: "set"}}

	req, printedHelp, err := parseCommandLine(schema, []string{"set", "--", "-1"}, "nebula ctl", io.Discard)
	require.NoError(t, err)
	assert.False(t, printedHelp)
	assert.Equal(t, commands.Name("set"), req.Name)
	assert.Nil(t, req.Params)
	assert.Equal(t, []string{"-1"}, req.Args)

	_, _, err = parseCommandLine(schema, []string{"set", "-1"}, "nebula ctl", io.Discard)
	require.ErrorContains(t, err, "flag provided but not defined: -1")
}

// TestRenderForTheFormatAsked: output follows the requested format; JSON strings stay
// quoted, and pretty printing keeps key order and precision.
func TestRenderForTheFormatAsked(t *testing.T) {
	text := &Response{Text: []byte("Log level is: info\n")}
	assert.Equal(t, "Log level is: info\n", text.render(commands.FormatUnset))
	assert.Equal(t, "Log level is: info\n", text.render(commands.FormatText))

	str := &Response{Result: json.RawMessage(`"some string"`)}
	assert.Equal(t, `"some string"`, str.render(commands.FormatJSON))
	assert.Equal(t, `"some string"`, str.render(commands.FormatPrettyJSON))

	// Keys stay in the order the daemon wrote them and a uint64 past 2^53 is not rounded,
	// which decoding into `any` and encoding again would do.
	obj := &Response{Result: json.RawMessage(`{"z":18446744073709551615,"a":{"y":[1,2],"b":true}}`)}
	//nolint:testifylint // the layout is what is under test, which JSONEq would not see
	assert.Equal(t, `{"z":18446744073709551615,"a":{"y":[1,2],"b":true}}`, obj.render(commands.FormatJSON))
	//nolint:testifylint // as above
	assert.Equal(t, "{\n    \"z\": 18446744073709551615,\n    \"a\": {\n        \"y\": [\n            1,\n            2\n        ],\n        \"b\": true\n    }\n}", obj.render(commands.FormatPrettyJSON))

	bad := &Response{Result: json.RawMessage(`{"a":`)}
	assert.Equal(t, `{"a":`, bad.render(commands.FormatPrettyJSON), "what cannot be indented is printed as it came")

	none := &Response{}
	assert.Empty(t, none.render(commands.FormatJSON))
	assert.Empty(t, none.render(commands.FormatUnset))
}

// TestParseCommandLinePointsAtTheClientsHelp: parse errors name prog, and -h writes to
// the given writer.
func TestParseCommandLinePointsAtTheClientsHelp(t *testing.T) {
	schema := []commands.CommandSchema{{Name: "change-remote"}}

	_, _, err := parseCommandLine(schema, []string{"change-remote", "-nope"}, "dnclient ctl", io.Discard)
	require.ErrorContains(t, err, "see 'dnclient ctl change-remote -h'")

	var help bytes.Buffer
	_, printedHelp, err := parseCommandLine(schema, []string{"change-remote", "-h"}, "dnclient ctl", &help)
	require.NoError(t, err)
	assert.True(t, printedHelp)
	assert.Contains(t, help.String(), "change-remote")
}

// TestParseCommandLineWithoutACommand: an empty argv is an error, not a panic.
func TestParseCommandLineWithoutACommand(t *testing.T) {
	_, printedHelp, err := parseCommandLine(nil, nil, "nebula ctl", io.Discard)
	require.EqualError(t, err, "no command given")
	assert.False(t, printedHelp)
}
