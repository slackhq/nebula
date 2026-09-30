package commands

import (
	"flag"
	"fmt"
	"maps"
	"slices"
)

// Request is one command to run, as every surface hands it to Invoke: the command, its
// options by name in the form their flags parse, and its operands.
//
// It is where the surfaces meet. An ssh line is parsed against the command's own FlagSet
// and becomes one of these through ParseLine; nebula ctl parses its line the same way
// against the schema and sends the pieces over the wire, where the control socket turns
// them back into one. From here on there is one path to the command.
type Request struct {
	// Command is the command to run, resolved by the surface at its edge. See
	// Registry.Resolve for the one that tells an unknown name from a withheld one.
	Command *Command

	// Params carries the options the line set, by flag name, each in the form its flag
	// parses from. An option left alone is absent, so the command's default applies.
	Params map[string]string

	// Args carries the operands: whatever the line did not consume as a flag.
	Args []string
}

// ParseLine reads a FlagSet that Parse has filled, and the operands it returned, into a
// Request. Command is left for the caller to set: it resolved the command before it
// could build the FlagSet. Every flag the line set travels by name in the form it parses
// from, which is what Invoke applies.
func ParseLine(fl *flag.FlagSet, operands []string) Request {
	req := Request{Args: operands}

	fl.Visit(func(f *flag.Flag) {
		if req.Params == nil {
			req.Params = map[string]string{}
		}
		req.Params[f.Name] = f.Value.String()
	})

	return req
}

// Invoke runs one Request, with w as the command's output.
//
// The parameters are applied by flag name, in name order: a request from the wire is a
// JSON object with no order of its own, and which of two bad parameters is reported must
// not change from one request to the next. An unknown parameter is an error rather than
// something quietly ignored, because a caller that misspells one deserves to hear about
// it instead of getting a default. A bad parameter means the command is never called,
// and the FlagSet is fresh for this call, so nothing set before it is seen by anyone.
func Invoke(req Request, w StringWriter) error {
	c := req.Command
	names := slices.Sorted(maps.Keys(req.Params))

	var fs any
	if c.Flags != nil {
		fl, box := c.Flags()
		fs = box

		if fl != nil {
			fl.SetOutput(w.Err())

			for _, k := range names {
				if fl.Lookup(k) == nil {
					return fmt.Errorf("%s has no parameter %q", c.Name, k)
				}

				if err := fl.Set(k, req.Params[k]); err != nil {
					return fmt.Errorf("%s: %w", k, err)
				}
			}
		} else if len(names) > 0 {
			return fmt.Errorf("%s takes no parameters", c.Name)
		}
	} else if len(names) > 0 {
		return fmt.Errorf("%s takes no parameters", c.Name)
	}

	return c.Callback(fs, req.Args, w)
}
