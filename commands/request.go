package commands

import (
	"flag"
	"maps"
	"slices"
)

// Request is one command to run, as every surface hands it to Invoke: the command, its
// options by name in the form their flags parse, its operands, and the rendering the
// line asked for, if any.
//
// nebula ctl builds one with ParseLine and it travels as a JSON object to the control
// socket. An ssh line never becomes one: it is parsed straight into the command's own
// FlagSet; see execLine.
type Request struct {
	// Command is the command to run, resolved by the surface at its edge. See
	// Registry.Resolve for the one that tells an unknown name from a withheld one.
	Command *Command

	// Params carries the options the line set, by flag name, each in the form its flag
	// parses from. An option left alone is absent, so the command's default applies.
	Params map[string]string

	// Args carries the operands: whatever the line did not consume as a flag.
	Args []string

	// Format is the rendering the line asked for with -json or -pretty, or FormatUnset
	// when it expressed no preference. It is ParseLine's reading of the line for the
	// client that sends the Request; Invoke does not read it, since the surface that
	// runs a Request renders with the format it agreed with its caller.
	Format Format
}

// ParseLine reads a FlagSet that ParseArgs has filled, and the operands it returned,
// into a Request to send over the wire. Command is left for the caller to set.
//
// Every flag the line set other than the presentation flags travels by name, as its
// flag's String, which is what the daemon's Set parses. That round trip is exact for
// the bool and string flags a client builds from the schema; it is the client's to make,
// and the ssh path does not make it, since it runs the FlagSet it parsed.
func ParseLine(fl *flag.FlagSet, operands []string) Request {
	req := Request{Args: operands, Format: presentationFormat(fl)}

	fl.Visit(func(f *flag.Flag) {
		if isPresentationFlag(f.Name) {
			return
		}
		if req.Params == nil {
			req.Params = map[string]string{}
		}
		req.Params[f.Name] = f.Value.String()
	})

	return req
}

// presentationFormat is the one reading of -json and -pretty from a parsed line, so a
// line means the same on every surface: only a flag set to true asks for JSON, since one
// set to false expresses no preference, and -pretty implies -json. FormatUnset means the
// line expressed no preference and the surface's own default applies.
func presentationFormat(fl *flag.FlagSet) Format {
	var asJSON, pretty bool
	fl.Visit(func(f *flag.Flag) {
		switch f.Name {
		case FlagJSON:
			asJSON = flagIsTrue(f)
		case FlagPretty:
			pretty = flagIsTrue(f)
		}
	})

	switch {
	case pretty:
		return FormatPrettyJSON
	case asJSON:
		return FormatJSON
	default:
		return FormatUnset
	}
}

// PresentationFormat is presentationFormat for a surface that takes a command's options
// by name rather than from a line: the info API's query string. Only the two presentation
// flags are read from params; the command's own parameters are the caller's to pass to
// Invoke, which refuses these two among them. A flag given with no value counts as set,
// as -pretty does on a line, and one that is not a boolean is a ParamError.
func PresentationFormat(params map[string]string) (Format, error) {
	fl := flag.NewFlagSet("", flag.ContinueOnError)
	addPresentationFlags(fl)

	for _, k := range []string{FlagJSON, FlagPretty} {
		v, ok := params[k]
		if !ok {
			continue
		}
		if v == "" {
			v = "true"
		}
		if err := setFlag(fl, fl.Lookup(k), v); err != nil {
			return FormatUnset, err
		}
	}

	return presentationFormat(fl), nil
}

// flagIsTrue reports whether a bool flag was set to true. The flag package's bool value
// is a flag.Getter whose Get returns the bool, so this never falls back to parsing text.
func flagIsTrue(f *flag.Flag) bool {
	g, ok := f.Value.(flag.Getter)
	if !ok {
		return false
	}
	b, _ := g.Get().(bool)
	return b
}

// Invoke runs one Request and returns the command's Result, unrendered.
//
// The parameters are applied by flag name, in name order: a request from the wire is a
// JSON object with no order of its own, and which of two bad parameters is reported must
// not change from one request to the next. An unknown parameter is an error rather than
// something quietly ignored, because a caller that misspells one deserves to hear about
// it instead of getting a default. A bad parameter means Run is never called, and the
// FlagSet is fresh for this call, so nothing set before it is seen by anyone.
//
// Nothing here writes anywhere and nothing here renders. What a surface does with the
// Result, marshal its Payload or run the command's own text rendering through Render,
// is the surface's decision, and keeping that out of here is what lets a caller tell a
// refusal from a success after the text has been produced. The presentation flags are
// not parameters: a Request says how it wants rendering in Format, and sending them as
// parameters is refused rather than read as a preference.
func Invoke(req Request) (Result, error) {
	c := req.Command

	fl, fs, own := commandFlags(c)
	if err := setParams(fl, string(c.Name), slices.Sorted(maps.Keys(req.Params)), req.Params, own); err != nil {
		return Result{}, err
	}

	return c.Run(fs, req.Args)
}
