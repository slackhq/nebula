package sshd

import (
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/armon/go-radix"
)

// CommandFlags is a function called before help or command execution to parse command line flags
// It should return a flag.FlagSet instance and a pointer to the struct that will contain parsed flags
type CommandFlags func() (*flag.FlagSet, any)

// CommandCallback is the function called when your command should execute.
// fs will be a a pointer to the struct provided by Command.Flags callback, if there was one. -h and -help are reserved
// and handled automatically for you.
// a will be any unconsumed arguments, if no Command.Flags was available this will be all the flags passed in.
// w is the writer to use when sending messages back to the client.
// If an error is returned by the callback it is logged locally, the callback should handle messaging errors to the user
// where appropriate
type CommandCallback func(fs any, a []string, w StringWriter) error

type Command struct {
	Name             string
	ShortDescription string
	Help             string
	Flags            CommandFlags
	Callback         CommandCallback
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

func dumpCommands(c *radix.Tree, w StringWriter) {
	err := w.WriteLine("Available commands:")
	if err != nil {
		return
	}

	cmds := make([]string, 0)
	for _, l := range allCommands(c) {
		cmds = append(cmds, fmt.Sprintf("%s - %s", l.Name, l.ShortDescription))
	}

	sort.Strings(cmds)
	_ = w.Write(strings.Join(cmds, "\n") + "\n\n")
}

func lookupCommand(c *radix.Tree, sCmd string) (*Command, error) {
	cmd, ok := c.Get(sCmd)
	if !ok {
		return nil, nil
	}

	command, ok := cmd.(*Command)
	if !ok {
		return nil, errors.New("failed to cast command")
	}

	return command, nil
}

func matchCommand(c *radix.Tree, cmd string) []string {
	cmds := make([]string, 0)
	c.WalkPrefix(cmd, func(found string, v any) bool {
		cmds = append(cmds, found)
		return false
	})
	sort.Strings(cmds)
	return cmds
}

func allCommands(c *radix.Tree) []*Command {
	cmds := make([]*Command, 0)
	c.WalkPrefix("", func(found string, v any) bool {
		cmd, ok := v.(*Command)
		if ok {
			cmds = append(cmds, cmd)
		}
		return false
	})
	return cmds
}

func helpCallback(commands *radix.Tree, a []string, w StringWriter) (err error) {
	// Just typed help
	if len(a) == 0 {
		dumpCommands(commands, w)
		return nil
	}

	// We are printing a specific commands help text
	cmd, err := lookupCommand(commands, a[0])
	if err != nil {
		return
	}

	if cmd != nil {
		err = w.WriteLine(fmt.Sprintf("%s - %s", cmd.Name, cmd.ShortDescription))
		if err != nil {
			return err
		}

		if cmd.Help != "" {
			err = w.WriteLine(fmt.Sprintf("  %s", cmd.Help))
			if err != nil {
				return err
			}
		}

		if cmd.Flags != nil {
			fs, _ := cmd.Flags()
			if fs != nil {
				fs.SetOutput(w.GetWriter())
				fs.PrintDefaults()
			}
		}

		return nil
	}

	err = w.WriteLine("Command not available " + a[0])
	if err != nil {
		return err
	}

	return nil
}

func checkHelpArgs(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "-help" {
			return true
		}
	}

	return false
}
