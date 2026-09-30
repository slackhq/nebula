package commands

import (
	"bytes"
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseLineCarriesWhatWasSetInParseableForm: only the flags the line set travel,
// each as the string its flag parses from, so Invoke can apply them to a fresh FlagSet
// and get the same values back. Operands come through untouched.
func TestParseLineCarriesWhatWasSetInParseableForm(t *testing.T) {
	type seen struct {
		Verbose bool
		Label   string
	}
	var got []seen

	r := New()
	r.Register(&Command{
		Name: "set",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := seen{}
			fl.BoolVar(&s.Verbose, "verbose", false, "say more")
			fl.StringVar(&s.Label, "label", "none", "a label")
			return fl, &s
		},
		Callback: func(fs any, a []string, w StringWriter) error {
			got = append(got, *fs.(*seen))
			return w.WriteLine("ran")
		},
	})

	fl, _ := r.Get("set").Flags()
	require.NoError(t, fl.Parse([]string{"-verbose", "x", "y"}))

	req := ParseLine(fl, fl.Args())
	assert.Equal(t, map[string]string{"verbose": "true"}, req.Params, "label was left alone and must be absent")
	assert.Equal(t, []string{"x", "y"}, req.Args)

	// The round trip: what ParseLine produced is what Invoke applies.
	req.Command = r.Get("set")
	out := &bytes.Buffer{}
	require.NoError(t, Invoke(req, NewStringWriter(out)))
	assert.Equal(t, "ran\n", out.String())
	assert.Equal(t, []seen{{Verbose: true, Label: "none"}}, got)
}

// TestResolveTellsUnknownFromWithheld: the two cases read differently to an operator,
// and Resolve is the edge that decides which one a name from the wire is.
func TestResolveTellsUnknownFromWithheld(t *testing.T) {
	r := testRegistry().Filter(notWithheld, testReason)

	c, err := r.Resolve("served")
	require.NoError(t, err)
	assert.Equal(t, Name("served"), c.Name)

	_, err = r.Resolve("withheld")
	require.ErrorContains(t, err, "withheld is not available on this surface")

	_, err = r.Resolve("no-such-command")
	require.ErrorContains(t, err, `unknown command "no-such-command"`)
}
