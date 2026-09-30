package commands

import (
	"flag"
)

// CommandFlags is called before help or command execution to parse command line flags.
// It should return a flag.FlagSet instance and a pointer to the struct that will contain parsed flags
type CommandFlags func() (*flag.FlagSet, any)

// CommandCallback is called when your command should execute.
// fs will be a a pointer to the struct provided by Command.Flags callback, if there was one. -h and -help are reserved
// and handled automatically for you.
// a will be any unconsumed arguments, if no Command.Flags was available this will be all the flags passed in.
// w is the writer to use when sending messages back to the client.
// If an error is returned by the callback it is logged locally, the callback should handle messaging errors to the user
// where appropriate
type CommandCallback func(fs any, a []string, w StringWriter) error

type Command struct {
	Name             Name
	ShortDescription string
	Help             string

	ForProfiling bool

	Flags    CommandFlags
	Callback CommandCallback
}

// execCommand runs a command line against c, reporting problems to w. It is the path
// from an ssh line to output: the line is parsed against the command's own FlagSet,
// becomes a Request, and Invoke runs it exactly as it runs the control socket's.
func execCommand(c *Command, args []string, w StringWriter) error {
	req := Request{Command: c, Args: args}

	if c.Flags != nil {
		if fl, _ := c.Flags(); fl != nil {
			// SetOutput() here in case fl.Parse dumps usage.
			fl.SetOutput(w.Err())
			if err := fl.Parse(args); err != nil {
				// fl.Parse has dumped error information to the user via the w writer.
				return err
			}
			req = ParseLine(fl, fl.Args())
			req.Command = c
		}
	}

	return Invoke(req, w)
}

// IsHelpRequest reports whether args ask for a command's help rather than running it.
// Both surfaces use it, so what counts as asking for help cannot drift between them: the
// ssh server answers with Registry.Help, and nebula ctl renders the same help locally
// from the schema.
func IsHelpRequest(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" {
			return true
		}
	}

	return false
}
