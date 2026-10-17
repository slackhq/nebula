package commands

import (
	"flag"
)

// CommandFlags is called before help or command execution to parse command line flags.
// It should return a flag.FlagSet instance and a pointer to the struct that will contain parsed flags
type CommandFlags func() (*flag.FlagSet, any)

// CommandCallback is called when your command should execute.
// fs will be a pointer to the struct provided by Command.Flags callback, if there was one. -h and -help are reserved
// and handled automatically for you.
// a will be any unconsumed arguments, if no Command.Flags was available this will be all the flags passed in.
// w is the writer to use when sending messages back to the client.
// An error returned by the callback is handed back to whoever dispatched the command, which reports a failure: exit
// status 1 over ssh. The error is not shown to the user. For a failure the user caused or can act on, write the
// message and return it as a *Failure, which Fail does in one step; the surface then reports the failure without
// logging what the user was already told. Any other error is logged by the surface as well.
type CommandCallback func(fs any, a []string, w StringWriter) error

type Command struct {
	Name             Name
	ShortDescription string
	Help             string

	Flags    CommandFlags
	Callback CommandCallback
}

// Failure is the error a command returns for a failure it has already explained to the user:
// the message it wrote is the whole story. A surface reports it as a failure and does not
// log it.
type Failure struct {
	Msg string
}

func (f *Failure) Error() string {
	return f.Msg
}

// Fail writes msg to w and returns it as a *Failure, so a command reports a failure to the
// user and to its surface in one line. If the write itself fails, that error is returned
// instead: the user was not told anything.
func Fail(w StringWriter, msg string) error {
	if err := w.WriteLine(msg); err != nil {
		return err
	}
	return &Failure{Msg: msg}
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
