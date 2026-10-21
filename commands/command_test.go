package commands

import (
	"bytes"
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseArgsAllowsFlagsAfterOperands pins the one way ParseArgs departs from fl.Parse,
// that a flag may follow an operand, and that it departs in no other: a negative number
// is a flag, as Parse reads it, and goes after "--" when it is meant as an operand.
func TestParseArgsAllowsFlagsAfterOperands(t *testing.T) {
	cases := map[string]struct {
		args     []string
		wantOps  []string
		wantN    string
		wantV    bool
		wantJSON bool
		wantErr  string
	}{
		"flag after operand":  {args: []string{"x", "-json"}, wantOps: []string{"x"}, wantJSON: true},
		"flags around":        {args: []string{"-v", "x", "-n", "1", "y"}, wantOps: []string{"x", "y"}, wantV: true, wantN: "1"},
		"value after operand": {args: []string{"x", "-n", "-1"}, wantOps: []string{"x"}, wantN: "-1"},
		"equals value":        {args: []string{"-n=-1", "x"}, wantOps: []string{"x"}, wantN: "-1"},
		"terminator after":    {args: []string{"x", "--", "-json", "-1"}, wantOps: []string{"x", "-json", "-1"}},
		"terminator":          {args: []string{"--", "-json"}, wantOps: []string{"-json"}},
		"defined numeric":     {args: []string{"-2", "x"}, wantOps: []string{"x"}, wantV: true},
		"negative number":     {args: []string{"-1"}, wantErr: "flag provided but not defined: -1"},
		"bad flag after":      {args: []string{"x", "-nope"}, wantErr: "flag provided but not defined: -nope"},
		"undefined flag":      {args: []string{"-nope", "x"}, wantErr: "flag provided but not defined: -nope"},
		"missing value":       {args: []string{"-n"}, wantErr: "flag needs an argument: -n"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fl := flag.NewFlagSet("t", flag.ContinueOnError)
			fl.SetOutput(&bytes.Buffer{})
			n := fl.String("n", "", "")
			v := fl.Bool("v", false, "")
			two := fl.Bool("2", false, "a flag that happens to be a number")
			asJSON := fl.Bool(FlagJSON, false, "")

			ops, err := ParseArgs(fl, tc.args)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantOps, ops)
			assert.Equal(t, tc.wantN, *n)
			assert.Equal(t, tc.wantV, *v || *two)
			assert.Equal(t, tc.wantJSON, *asJSON)
		})
	}
}

// TestDispatchFlagAfterOperand: the same through a registered command with no Flags of
// its own, which only has the presentation flags to find.
func TestDispatchFlagAfterOperand(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, testRegistry().DispatchArgs([]string{"served", "x", "-json"}, MergedOutput(out)))
	assert.Equal(t, "\"read x\"\n", out.String())
}

// TestLookupArg pins the reading of an argument's shape that ParseArgs and nebula ctl
// share.
func TestLookupArg(t *testing.T) {
	fl := flag.NewFlagSet("t", flag.ContinueOnError)
	fl.String("n", "", "")
	fl.Bool("v", false, "")

	for _, tc := range []struct {
		arg      string
		name     string
		hasValue bool
	}{
		{"-n", "n", false},
		{"--n", "n", false},
		{"-n=1", "n", true},
		{"--n=", "n", true},
		{"-v", "v", false},
		{"-nope", "", false},
		{"-1", "", false},
	} {
		f, hasValue := LookupArg(fl, tc.arg)
		if tc.name == "" {
			assert.Nil(t, f, tc.arg)
		} else {
			require.NotNil(t, f, tc.arg)
			assert.Equal(t, tc.name, f.Name, tc.arg)
		}
		assert.Equal(t, tc.hasValue, hasValue, tc.arg)
	}

	assert.True(t, IsBoolFlag(fl.Lookup("v")))
	assert.False(t, IsBoolFlag(fl.Lookup("n")))
}
