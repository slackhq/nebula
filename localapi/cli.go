package localapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/slackhq/nebula/commands"
)

// InvokeLine parses argv (a command word and its arguments) against the server's schema,
// runs it, and returns the output rendered in the requested format. A command's -h
// writes its help to help and returns empty. prog is the client's name, e.g. "nebula ctl",
// used in parse errors.
//
// A *DaemonError means the server refused the request; its message is meant to be
// printed as is. Other errors describe a bad line or an unreachable socket. A refusal
// requested as JSON is also rendered into out.
func (c *Client) InvokeLine(argv []string, prog string, help io.Writer) (out string, err error) {
	schema, err := c.Describe()
	if err != nil {
		var refused *DaemonError
		var unread *ReplyError
		if errors.As(err, &refused) || errors.As(err, &unread) {
			return "", err
		}
		return "", fmt.Errorf("could not reach the control socket at %s: %w", c.Path, err)
	}

	line, printedHelp, err := parseCommandLine(schema, argv, prog, help)
	if err != nil || printedHelp {
		return "", err
	}

	res, err := c.Invoke(string(line.Name), line.Params, line.Args, wireFormat(line.Format))
	if err != nil {
		return "", err
	}

	out = res.render(line.Format)
	if res.Error != "" {
		return out, &DaemonError{Msg: res.Error}
	}
	return out, nil
}

// render returns the response in format. JSON is re-indented rather than re-encoded, to
// keep key order and number precision.
func (res *Response) render(format commands.Format) string {
	switch format {
	case commands.FormatJSON:
		return string(res.Result)
	case commands.FormatPrettyJSON:
		var buf bytes.Buffer
		if err := json.Indent(&buf, res.Result, "", "    "); err != nil {
			return string(res.Result)
		}
		return buf.String()
	default:
		return string(res.Text)
	}
}

// commandLine is a parsed command line. Request.Command is nil, and Format is
// FormatUnset when the line didn't choose one.
type commandLine struct {
	Name commands.Name
	commands.Request
}

// wireFormat maps a line's format to the request's: JSON for -json and -pretty, which is
// indented client side, and text otherwise.
func wireFormat(f commands.Format) string {
	switch f {
	case commands.FormatJSON, commands.FormatPrettyJSON:
		return "json"
	default:
		return "text"
	}
}

// parseCommandLine parses argv against schema with the same rules the server applies
// to an ssh line. printedHelp is true when -h wrote the command's help to help.
func parseCommandLine(schema []commands.CommandSchema, argv []string, prog string, help io.Writer) (req commandLine, printedHelp bool, err error) {
	if len(argv) == 0 {
		return commandLine{}, false, errors.New("no command given")
	}
	name := commands.Name(argv[0])

	var found *commands.CommandSchema
	for i := range schema {
		if schema[i].Name == name {
			found = &schema[i]
			break
		}
	}

	if found == nil {
		// Unknown here; the server's error distinguishes a typo from a withheld command.
		return commandLine{Name: name, Request: commands.Request{Args: argv[1:]}}, false, nil
	}

	// Silenced: flag's usage output doesn't match WriteCommandHelp's layout.
	fs := flag.NewFlagSet(string(name), flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	for _, f := range found.Flags {
		if f.Bool {
			fs.Bool(f.Name, f.Default == "true", f.Usage)
			continue
		}
		fs.String(f.Name, f.Default, f.Usage)
	}

	operands, err := commands.ParseArgs(fs, argv[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_ = commands.WriteCommandHelp(*found, help)
			return commandLine{}, true, nil
		}
		return commandLine{}, false, fmt.Errorf("%s: %s (see '%s %s -h')", name, err, prog, name)
	}

	// Only flags that were set are sent, so the server applies its own defaults.
	return commandLine{Name: name, Request: commands.ParseLine(fs, operands)}, false, nil
}
