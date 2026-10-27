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

// The pieces of a command line client for the control socket that do not depend on
// which program it is part of: nebula ctl is one, and a program that embeds nebula and
// serves the socket with WireControl can offer the same command line with them. Dialing
// is Client's; which socket to dial, and what the client's own flags are, is the
// program's.

// Render returns what the daemon answered, for the format the line asked for. A text
// request is answered in Text with the bytes the command wrote, printed as they are; a
// JSON request is answered in Result with the value itself, printed as it came, since a
// value that happens to be a string is still JSON to the script reading it. Indentation
// is the client's business: whitespace does not survive a JSON envelope, and the daemon
// has no reason to care how its answer is laid out. The bytes are re-indented rather
// than decoded and encoded again, which would sort the keys and round the numbers.
func (res *Response) Render(format commands.Format) string {
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

// CommandLine is one parsed command line for a control socket client such as nebula
// ctl: the command's name, which only the daemon can resolve, and the line as every
// surface parses it. The Request's Command is nil here, since a client holds a schema
// rather than the command, and its Format is FormatUnset when the line named none,
// which to a command line client means text: its default differs from the API's.
type CommandLine struct {
	Name commands.Name
	commands.Request
}

// WireFormat is what a request asks the daemon for, as Client.Invoke takes it. Pretty is the client's business,
// since whitespace does not survive a JSON envelope, so it travels as json. No
// preference is text, a command line client's default: a person gets the human rendering wherever
// one exists.
func WireFormat(f commands.Format) string {
	switch f {
	case commands.FormatJSON, commands.FormatPrettyJSON:
		return "json"
	default:
		return "text"
	}
}

// ParseCommandLine turns the user's command line into a CommandLine, using the schema the
// daemon supplied. The line is parsed with the same rules the daemon applies to an ssh
// line, through ParseArgs, and ParseLine reads what was set into the Request to send, so
// a line means the same on both.
//
// printedHelp reports that the command's help was written to help instead, and there is
// nothing to send. prog is the client as the operator typed it, "nebula ctl", which a
// parse error points back at; the error is not prefixed with the program's name, which
// is the caller's to add.
func ParseCommandLine(schema []commands.CommandSchema, argv []string, prog string, help io.Writer) (req CommandLine, printedHelp bool, err error) {
	name := commands.Name(argv[0])

	var found *commands.CommandSchema
	for i := range schema {
		if schema[i].Name == name {
			found = &schema[i]
			break
		}
	}

	if found == nil {
		// Let the daemon answer. It knows whether this is a typo or a command it holds
		// back, and its message for the second case is better than anything guessable
		// from the schema alone.
		return CommandLine{Name: name, Request: commands.Request{Args: argv[1:]}}, false, nil
	}

	// The flag package's own report is a bare message followed by a usage dump in a layout
	// that does not match WriteCommandHelp, so it is silenced and the error is reported
	// once, below, with a pointer at the help this command actually prints.
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
			// The same rendering the daemon uses for `help <command>`, so -h and help agree.
			_ = commands.WriteCommandHelp(*found, help)
			return CommandLine{}, true, nil
		}

		// Say what flag did: an unknown flag, a missing value and a malformed value are
		// different mistakes, and "does not take" would be wrong for two of them.
		return CommandLine{}, false, fmt.Errorf("%s: %s (see '%s %s -h')", name, err, prog, name)
	}

	// Only what the user actually set travels. A parameter left alone is the daemon's
	// default to apply, not the client's to assert, and the presentation flags are the
	// client's to interpret, never sent.
	//
	// Where the command has no human form the daemon says so, and only once the command
	// has run: a refusal ("No vpn address was provided") always has a human form, so
	// telling the user to pass -json before finding out whether the command would even
	// accept the line sends them to fix the wrong thing. That is why the schema does not
	// say which commands have a human form: nothing should decide on it before running.
	return CommandLine{Name: name, Request: commands.ParseLine(fs, operands)}, false, nil
}

// SplitCommandLine divides a client's line, nebula ctl's, into the client's own flags, for fs to parse, and
// the command line to send, which begins with the command word. The client's flags may
// come before the command or after it: `nebula ctl -config x identity` and
// `nebula ctl identity -config x` mean the same, so an operator who has typed a command
// and then remembers which daemon they meant does not have to retype the line.
//
// Before the command word every flag is the client's, whatever it is, so an unknown one
// is reported by fs, and -h is the client's usage. After it only the
// flags fs defines are lifted out, and only those: the command's own flags are unknown
// here, since they come from the daemon the line has yet to name, and -h after the
// command asks for that command's help. Which command flags take a value is unknown too,
// so the client's names are reserved in the commands package and no command can give
// one a value that would be lifted from here. A "--" before the command is consumed, as
// fs.Parse would have; one after it belongs to the command line and ends the lifting,
// so an operand spelled like a client flag can still be passed.
func SplitCommandLine(fs *flag.FlagSet, args []string) (own, cmd []string) {
	seenCommand := false
	for i := 0; i < len(args); i++ {
		a := args[i]

		if a == "--" {
			if seenCommand {
				return own, append(cmd, args[i:]...)
			}
			seenCommand = true
			continue
		}

		if !seenCommand {
			if len(a) < 2 || a[0] != '-' {
				seenCommand = true
				cmd = append(cmd, a)
				continue
			}

			own = append(own, a)
			if f, hasValue := commands.LookupArg(fs, a); f != nil && !hasValue && !commands.IsBoolFlag(f) && i+1 < len(args) {
				i++
				own = append(own, args[i])
			}
			continue
		}

		if len(a) >= 2 && a[0] == '-' {
			// The same reading of the argument ParseArgs makes, so a word this lifts as a
			// client flag's value is one the daemon's parser would have read the same way.
			if f, hasValue := commands.LookupArg(fs, a); f != nil {
				own = append(own, a)
				if !hasValue && !commands.IsBoolFlag(f) && i+1 < len(args) {
					i++
					own = append(own, args[i])
				}
				continue
			}
		}

		cmd = append(cmd, a)
	}

	return own, cmd
}
