package commands

import (
	"bytes"
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseArgsKeepsNegativeOperands pins the two ways ParseArgs departs from fl.Parse:
// a negative number is an operand, and a flag may follow an operand.
func TestParseArgsKeepsNegativeOperands(t *testing.T) {
	cases := map[string]struct {
		args     []string
		wantOps  []string
		wantN    string
		wantV    bool
		wantJSON bool
		wantErr  string
	}{
		"bare":               {args: []string{"-1"}, wantOps: []string{"-1"}},
		"decimal":            {args: []string{"-1.5"}, wantOps: []string{"-1.5"}},
		"double dash":        {args: []string{"--1"}, wantOps: []string{"--1"}},
		"after bool flag":    {args: []string{"-v", "-1"}, wantOps: []string{"-1"}, wantV: true},
		"after json flag":    {args: []string{"-json", "-1"}, wantOps: []string{"-1"}, wantJSON: true},
		"as a flag value":    {args: []string{"-n", "-1", "x"}, wantOps: []string{"x"}, wantN: "-1"},
		"as an equals value": {args: []string{"-n=-1", "-3"}, wantOps: []string{"-3"}, wantN: "-1"},
		"flag after operand": {args: []string{"-1", "-json"}, wantOps: []string{"-1"}, wantJSON: true},
		"flags around":       {args: []string{"-v", "x", "-n", "-1", "y"}, wantOps: []string{"x", "y"}, wantV: true, wantN: "-1"},
		"terminator after":   {args: []string{"x", "--", "-json", "-1"}, wantOps: []string{"x", "-json", "-1"}},
		"bad flag after":     {args: []string{"x", "-nope"}, wantErr: "flag provided but not defined: -nope"},
		"terminator":         {args: []string{"--", "-json"}, wantOps: []string{"-json"}},
		"defined numeric":    {args: []string{"-2", "-1"}, wantOps: []string{"-1"}, wantV: true},
		"not a number":       {args: []string{"-1x"}, wantErr: "flag provided but not defined: -1x"},
		"undefined flag":     {args: []string{"-nope", "-1"}, wantErr: "flag provided but not defined: -nope"},
		"missing value":      {args: []string{"-n"}, wantErr: "flag needs an argument: -n"},
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

// TestDispatchNegativeOperand: the same through a registered command with no Flags of
// its own, which is the shape of mutex-profile-fraction.
func TestDispatchNegativeOperand(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, testRegistry().DispatchArgs([]string{"served", "-1"}, "", MergedOutput(out)))
	assert.Equal(t, "read -1\n", out.String())

	out.Reset()
	require.NoError(t, testRegistry().DispatchArgs([]string{"served", "-json", "-1"}, "", MergedOutput(out)))
	assert.Equal(t, "\"read -1\"\n", out.String())
}
