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

	Flags    CommandFlags
	Callback CommandCallback
}

func execCommand(c *Command, args []string, w StringWriter) error {
	var (
		fl *flag.FlagSet
		fs any
	)

	if c.Flags != nil {
		fl, fs = c.Flags()
		if fl != nil {
			// SetOutput() here in case fl.Parse dumps usage.
			fl.SetOutput(w.GetWriter())
			err := fl.Parse(args)
			if err != nil {
				// fl.Parse has dumped error information to the user via the w writer.
				return err
			}
			args = fl.Args()
		}
	}

	return c.Callback(fs, args, w)
}

func checkHelpArgs(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "-help" {
			return true
		}
	}

	return false
}
