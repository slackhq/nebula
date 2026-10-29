package commands

import (
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func lineFlags() *flag.FlagSet {
	fl := flag.NewFlagSet("set", flag.ContinueOnError)
	fl.Bool("verbose", false, "")
	fl.Duration("wait", 0, "")
	fl.String("label", "none", "")
	fl.Bool(FlagJSON, false, "")
	fl.Bool(FlagPretty, false, "")
	return fl
}

// TestParseLineReadsThePresentationFlagsOnce: presentationFormat is the one reading of
// -json and -pretty, for every surface, and ParseLine carries its answer. A flag set to
// false expresses no preference, and neither flag ever travels as a parameter.
func TestParseLineReadsThePresentationFlagsOnce(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want Format
	}{
		{nil, FormatUnset},
		{[]string{"-json=false"}, FormatUnset},
		{[]string{"-pretty=false"}, FormatUnset},
		{[]string{"-json"}, FormatJSON},
		{[]string{"-pretty"}, FormatPrettyJSON},
		{[]string{"-pretty", "-json=false"}, FormatPrettyJSON},
	} {
		fl := lineFlags()
		operands, err := ParseArgs(fl, tc.args)
		require.NoError(t, err)

		req := ParseLine(fl, operands)
		assert.Equal(t, tc.want, req.Format, "%v", tc.args)
		assert.Nil(t, req.Params, "%v: presentation flags are not parameters", tc.args)
	}
}

// TestParseLineCarriesWhatWasSetInParseableForm: only the flags the line set travel,
// each as the string its flag parses from, so the daemon's Invoke can apply them to a
// fresh FlagSet and get the same values back. Operands come through untouched, those
// after "--" included.
func TestParseLineCarriesWhatWasSetInParseableForm(t *testing.T) {
	fl := lineFlags()
	operands, err := ParseArgs(fl, []string{"-verbose", "-wait", "2s", "x", "--", "-1"})
	require.NoError(t, err)

	req := ParseLine(fl, operands)
	assert.Equal(t, map[string]string{"verbose": "true", "wait": "2s"}, req.Params, "label was left alone and must be absent")
	assert.Equal(t, []string{"x", "-1"}, req.Args)
	assert.Equal(t, FormatUnset, req.Format)

	// The round trip a client makes: what ParseLine produced is what Invoke applies.
	r, seen := paramRegistry(t)
	req.Command = r.Get("set")
	_, err = Invoke(req)
	require.NoError(t, err)
	require.Len(t, *seen, 1)
	assert.Equal(t, paramsSeen{Verbose: true, Wait: 2 * time.Second}, (*seen)[0])
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

// TestLineRunsTheFlagSetItParsed: the ssh path hands Run the FlagSet the line was parsed
// into, with no trip through a Request. A flag.Func has no String worth re-parsing, so a
// round trip would hand Run an empty value and no error; the line's value must arrive.
func TestLineRunsTheFlagSetItParsed(t *testing.T) {
	var seen []string
	r := New()
	r.Register(&Command{
		Name: "mode",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := new(string)
			fl.Func("mode", "the mode", func(v string) error {
				*s = "set:" + v
				return nil
			})
			return fl, s
		},
		Run: func(fs any, a []string) (Result, error) {
			seen = append(seen, *fs.(*string))
			return Value("ok"), nil
		},
	})

	var out, errw strings.Builder
	r.Dispatch("mode -json -mode fast", Output{Out: &out, Err: &errw})
	require.Equal(t, []string{"set:fast"}, seen)
	assert.Empty(t, errw.String())
	assert.Equal(t, "\"ok\"\n", out.String(), "-json was read from the same FlagSet")
}
