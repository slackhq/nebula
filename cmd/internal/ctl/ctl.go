package ctl

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/localapi"
)

// Word is the argument that selects the control client instead of the daemon.
const Word = "ctl"

// Subcommand handles the one bare word a daemon binary accepts before its flags. `nebula
// ctl <command>` runs the client. Any other first argument that is not a flag is a
// mistyped subcommand, reported with a usage line: the daemon's flag parser would ignore
// the stray word and start nebula, so `nebula clt` would bring up a second daemon
// instead of reporting a typo. It returns the exit code and true when the process is
// done, and false when argv is the daemon's to parse. Both daemon binaries, cmd/nebula
// and cmd/nebula-service, call it before anything else, so each has a nebula ctl and
// neither has the hazard. A word that follows the daemon's flags instead is Trailing's.
func Subcommand(argv []string) (code int, done bool) {
	if len(argv) < 2 || strings.HasPrefix(argv[1], "-") {
		return 0, false
	}

	if argv[1] == Word {
		return Run(argv[2:]), true
	}

	return unknownCommand(argv[1]), true
}

// Trailing handles the words the daemon's flag parser leaves unparsed: flag.Parse stops
// at the first argument that is not a flag and hands the rest back. rest is flag.Args()
// after the daemon has parsed, and configPath is the config the daemon's -config named,
// "" when it did not. Both daemon binaries call it right after flag.Parse, so that
// `nebula -config x ctl identity` runs the client and `nebula -config x clt` reports a
// typo, as Subcommand does for a word at the front of the line; a daemon that ignored
// the words would start in their place.
//
// A leading ctl word runs the client on what follows, with the daemon's -config carried
// over: an operator who typed it meant the daemon running on that config, and the client
// derives the same socket from it. Any other word is a mistake, reported as Subcommand
// reports one.
func Trailing(rest []string, configPath string) (code int, done bool) {
	if len(rest) == 0 {
		return 0, false
	}

	if rest[0] != Word {
		return unknownCommand(rest[0]), true
	}

	args := rest[1:]
	if configPath != "" {
		// First, so a -config on the ctl side of the line still wins: Parse applies
		// flags in order and the last value set is the one read.
		args = append([]string{"-" + commands.FlagConfig, configPath}, args...)
	}

	return Run(args), true
}

// unknownCommand reports a bare word that is neither a flag nor ctl, with the one usage
// line that says what the two forms of the command line are.
func unknownCommand(word string) int {
	fmt.Fprintf(os.Stderr, "nebula: unknown command %q\n\n", word)
	fmt.Fprintf(os.Stderr, "Run nebula with flags to start it, or `nebula %s <command>` to control one that is already running.\n", Word)
	return 1
}

// Run implements `nebula ctl <command> [args]`
//
// args is everything after the `ctl` word.
func Run(args []string) int {
	fs := flag.NewFlagSet("nebula ctl", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	configPath := fs.String(commands.FlagConfig, "", "Path to the config of the running nebula, used to locate its control socket")
	socketPath := fs.String(commands.FlagSocket, "", "Path to the control socket, instead of the one the config implies")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nebula ctl [flags] <command> [command flags]\n\n")
		fmt.Fprintf(os.Stderr, "Inspects and controls a nebula already running on this machine.\n")
		fmt.Fprintf(os.Stderr, "Run it as the user who ran nebula, or as a member of the group %s names.\n\n", localapi.CtlGroupKey)
		fmt.Fprintf(os.Stderr, "Flags, which may come before or after the command:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nRun `nebula ctl help` for the available commands.\n")
	}

	own, cmdArgs := splitLine(fs, args)
	if err := fs.Parse(own); err != nil {
		// fs has already printed the usage, or the problem. Asking for help is not a
		// failure, and a script that chains on `nebula ctl -h` should not see one.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	if len(cmdArgs) == 0 {
		cmdArgs = []string{"help"}
	}

	path, err := resolveSocket(*socketPath, *configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}

	client := &localapi.Client{Path: path}

	out, err := client.InvokeLine(cmdArgs, "nebula "+Word, os.Stdout)
	if out != "" {
		fmt.Fprint(os.Stdout, out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Fprintln(os.Stdout)
		}
	}

	if err == nil {
		return 0
	}

	// A JSON refusal is already on stdout.
	if out != "" {
		return 1
	}

	// Refusals are printed as is; other errors get a prefix.
	var refused *localapi.DaemonError
	if !errors.As(err, &refused) {
		fmt.Fprintf(os.Stderr, "nebula: %s\n", err)
		return 1
	}

	msg := refused.Msg
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, msg)
	return 1
}

// splitLine splits args into the client's flags (own) and the command line (cmd).
// Before the command word every flag is the client's. After it, only flags defined on fs
// are lifted, which is safe because commands can't declare reserved client flags. A "--"
// after the command word ends lifting.
func splitLine(fs *flag.FlagSet, args []string) (own, cmd []string) {
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
			// Parsed as ParseArgs would, so lifted values match the server's reading.
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

// resolveSocket decides which socket to talk to. It never searches: the answer is the
// socket the operator named, or the one the config implies, and nothing else.
//
// An explicit flag wins. Otherwise the config is read, the one the operator named or the
// one found next to the executable, and the path is the socket that config implies: its
// local_api.control.socket if set, else the same derivation the daemon applies.
func resolveSocket(socketFlag, configFlag string) (string, error) {
	if socketFlag != "" {
		return socketFlag, nil
	}

	return pathFromConfig(configFlag)
}

// pathFromConfig returns the socket path the daemon would be serving: the one
// local_api.control.socket names in the config, so an operator who moved the socket does
// not have to repeat themselves on every invocation, else the default.
//
// A config the operator did not name is a guess: config.DefaultPath looks next to the
// executable, and a package that installs a default config there while systemd starts
// the daemon with another will make it the wrong guess. It is still the only answer
// that involves no searching. A guess that cannot be read is not an error, it is no
// guess: a member of the socket's group cannot read a root daemon's config, and is
// answered by the default path, where the daemon serves unless that config moved it.
// A config the operator named is theirs to make readable.
func pathFromConfig(configFlag string) (string, error) {
	return socketFromConfigFile(configFlag, configFlag != "")
}

func socketFromConfigFile(configPath string, named bool) (string, error) {
	if !named {
		p, err := config.DefaultPath()
		if err != nil {
			return localapi.DefaultSocketPath, nil
		}
		configPath = p
	}

	// The config is loaded only to find the socket path. Loading logs lines that belong
	// to the daemon, not to someone running a read only command, and mixing them into
	// the CLI's output would corrupt a -json result, so they are discarded.
	c := config.NewC(slog.New(slog.DiscardHandler))
	if err := c.Load(configPath); err != nil {
		if !named {
			return localapi.DefaultSocketPath, nil
		}
		// The operating system's error, as it came: permission denied on a root daemon's
		// config says what to do.
		return "", fmt.Errorf("nebula: could not read %s: %w", configPath, err)
	}

	// A daemon running this config serves no socket; dialing the path would only say
	// that nothing is there.
	if !localapi.ControlEnabled(c) {
		return "", fmt.Errorf("nebula: the control socket is disabled in %s by %s", configPath, localapi.CtlEnabledKey)
	}

	// The same call the daemon makes, so the two agree on the path and on what makes a
	// path unusable.
	p, err := localapi.SocketPathFromConfig(c)
	if err != nil {
		return "", fmt.Errorf("nebula: %w", err)
	}

	return p, nil
}
