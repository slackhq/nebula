package ctl

import (
	"errors"
	"flag"
	"fmt"
	"io"
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
		args = append([]string{"-config", configPath}, args...)
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

	configPath := fs.String("config", "", "Path to the config of the running nebula, used to locate its control socket")
	socketPath := fs.String("socket", "", "Path to the control socket, instead of the one the config implies")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nebula ctl [flags] <command> [command flags]\n\n")
		fmt.Fprintf(os.Stderr, "Inspects and controls a nebula already running on this machine.\n")
		fmt.Fprintf(os.Stderr, "Run it as the user who ran nebula; nobody else can connect.\n\n")
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

	path, usedConfig, overrideIn, err := resolveSocket(*socketPath, *configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}

	client := &localapi.Client{Path: path}

	// Ask the daemon what it serves before parsing anything. The flags belong to the
	// command, which lives over there, so this is what lets the CLI keep its usual shape
	// while the wire protocol stays a named-parameter API rather than a shipped argv.
	schema, err := client.Describe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nebula: could not reach the control socket at %s: %s\n", path, err)
		if *socketPath == "" {
			// The path was computed, and the daemon computes its own from its environment.
			// When the config names the path, the usual way the two disagree is time: the
			// key was edited and the daemon has not reloaded yet, which is exactly what
			// `nebula ctl reload` against that config runs into. Otherwise it is privilege:
			// nebula runs as root for the tun device and this does not, so say that when it
			// is what happened. Failing both, the daemon's log says where its socket is.
			if overrideIn != "" {
				fmt.Fprintf(os.Stderr, "The path is %s in %s. A daemon that has not reloaded since that key changed is still serving the old path: pass it with -socket <old path>, or reload the daemon another way, such as SIGHUP.\n", localapi.CtlSocketKey, overrideIn)
			} else if rootPath, ok := localapi.ServedByRootFor(usedConfig); ok {
				fmt.Fprintf(os.Stderr, "nebula is running as root and serving %s; run nebula ctl with sudo.\n", rootPath)
			} else {
				fmt.Fprintf(os.Stderr, "If nebula runs with another config, pass -config <path>. The daemon logs its socket path at startup; pass it with -socket <path>.\n")
			}
		}
		return 1
	}

	req, printedHelp, err := parseCommand(schema, cmdArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}

	if printedHelp {
		return 0
	}

	res, err := client.Invoke(string(req.name), wireParams(req.Params), req.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nebula: %s\n", err)
		return 1
	}

	out := localapi.Text(res.Result)

	// Indentation is the client's business: whitespace does not survive a JSON envelope,
	// and the daemon has no reason to care how its answer is laid out.
	if req.Params["pretty"] == "true" {
		if indented, ok := localapi.Pretty(res.Result); ok {
			out = indented
		}
	}

	if out != "" {
		fmt.Fprint(os.Stdout, out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Fprintln(os.Stdout)
		}
	}

	if res.Error == "" {
		return 0
	}

	msg := res.Error
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Fprint(os.Stderr, msg)

	return 1
}

// ctlRequest is one parsed nebula ctl command line: the command's name, which only the
// daemon can resolve, and the line as every surface parses it. The Request's Command is
// nil here, since the CLI holds a schema rather than the command.
type ctlRequest struct {
	name commands.Name
	commands.Request
}

// wireParams carries the line's options as the wire takes them: the strings the flags
// parsed from, which the daemon applies the same way as JSON's own types.
func wireParams(in map[string]string) map[string]any {
	if len(in) == 0 {
		return nil
	}

	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// parseCommand turns the user's command line into a ctlRequest, using the schema the
// daemon supplied. The line is parsed with the same rules the daemon applies to an ssh
// line, through ParseLine, so a line means the same on both.
//
// printedHelp reports that help was written for the command instead, and there is
// nothing to send.
func parseCommand(schema []commands.CommandSchema, argv []string) (req ctlRequest, printedHelp bool, err error) {
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
		return ctlRequest{name: name, Request: commands.Request{Args: argv[1:]}}, false, nil
	}

	if commands.IsHelpRequest(argv[1:]) {
		printCommandHelp(found)
		return ctlRequest{}, true, nil
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

	if err := fs.Parse(argv[1:]); err != nil {
		// Say what flag did: an unknown flag, a missing value and a malformed value are
		// different mistakes, and "does not take" would be wrong for two of them.
		return ctlRequest{}, false, fmt.Errorf("nebula: %s: %s (see 'nebula ctl %s -h')", name, err, name)
	}

	// Only what the user actually set travels. A parameter left alone is the daemon's
	// default to apply, not the client's to assert.
	return ctlRequest{name: name, Request: commands.ParseLine(fs, fs.Args())}, false, nil
}

// splitLine divides a nebula ctl line into the client's own flags, for fs to parse, and
// the command line to send, which begins with the command word. The client's flags may
// come before the command or after it: `nebula ctl -config x identity` and
// `nebula ctl identity -config x` mean the same, so an operator who has typed a command
// and then remembers which daemon they meant does not have to retype the line.
//
// Before the command word every flag is the client's, whatever it is, so an unknown one
// is reported by fs as it always was, and -h is the client's usage. After it only the
// flags fs defines are lifted out, and only those: the command's own flags are unknown
// here, since they come from the daemon the line has yet to name, and -h after the
// command asks for that command's help. Which command flags take a value is unknown too,
// so the client's names are its alone: a command must not give one a value here. A "--"
// before the command is consumed, as fs.Parse would have; one after it belongs to the
// command line and ends the lifting, so an operand spelled like a client flag can still
// be passed.
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
			if f, hasValue := ownFlag(fs, a); f != nil && !hasValue && takesValue(f) && i+1 < len(args) {
				i++
				own = append(own, args[i])
			}
			continue
		}

		if len(a) >= 2 && a[0] == '-' {
			if f, hasValue := ownFlag(fs, a); f != nil {
				own = append(own, a)
				if !hasValue && takesValue(f) && i+1 < len(args) {
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

// ownFlag returns the flag of fs that the argument a names, nil when it names none, and
// whether a carries its value after an "=".
func ownFlag(fs *flag.FlagSet, a string) (f *flag.Flag, hasValue bool) {
	name := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
	if eq := strings.IndexByte(name, '='); eq >= 0 {
		name, hasValue = name[:eq], true
	}
	return fs.Lookup(name), hasValue
}

// takesValue reports whether f reads the argument after it as its value, which every
// flag does except a boolean.
func takesValue(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !ok || !bf.IsBoolFlag()
}

// resolveSocket decides which socket to talk to. It never searches: the answer is the
// socket the operator named, or the one the config implies, and nothing else.
//
// An explicit flag wins. Otherwise the config is read, the one the operator named or the
// one found next to the executable, and the path is the socket that config implies: its
// local_api.control.socket if set, else the same derivation the daemon applies.
// configPath is the config that was read, "" when none was; overrideIn is that config
// when its key set the path, and "" when the path was derived or named on the command
// line.
func resolveSocket(socketFlag, configFlag string) (path, configPath, overrideIn string, err error) {
	if socketFlag != "" {
		return socketFlag, "", "", nil
	}

	return pathFromConfig(configFlag)
}

// pathFromConfig reads a nebula config and returns the socket path that daemon would be
// serving, honouring the optional local_api.control.socket override so an operator who
// moved the socket does not have to repeat themselves on every invocation. configPath
// is the config that was read, and overrideIn is the same path when the override is
// what answered.
//
// A config the operator did not name is a guess: config.DefaultPath looks next to the
// executable, and a package that installs a default config there while systemd starts
// the daemon with another will make it the wrong guess. It is still the only answer
// that involves no searching, and the dial error then names a real path and says what
// to pass.
func pathFromConfig(configFlag string) (path, configPath, overrideIn string, err error) {
	configPath = configFlag
	if configPath == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return "", "", "", fmt.Errorf("nebula: no config found next to the executable (%s); pass -config <path> or -socket <path>", err)
		}
		configPath = p
	}

	// The config is loaded only to find the socket path. Loading logs lines that belong
	// to the daemon, not to someone running a read only command, and mixing them into
	// the CLI's output would corrupt a -json result, so they are discarded.
	c := config.NewC(slog.New(slog.DiscardHandler))
	if err := c.Load(configPath); err != nil {
		return "", "", "", fmt.Errorf("nebula: could not read %s: %s", configPath, err)
	}

	// The same call the daemon makes, so the two agree on the path and on what makes a
	// path unusable.
	p, err := localapi.SocketPathFromConfig(c, configPath)
	if err != nil {
		// A derivation that fails here, for this user, says what the daemon's operator
		// should do about it. When the daemon is already up as root that is the wrong
		// advice: the socket exists, it is root's, and the fix is sudo. Only a derived
		// path is probed; an override is wherever it says, hashed or not.
		if c.GetString(localapi.CtlSocketKey, "") == "" {
			if rootPath, ok := localapi.ServedByRootFor(configPath); ok {
				return "", "", "", fmt.Errorf("nebula: nebula is running as root and serving %s; run nebula ctl with sudo", rootPath)
			}
		}
		return "", "", "", fmt.Errorf("nebula: %s", err)
	}

	if c.GetString(localapi.CtlSocketKey, "") != "" {
		overrideIn = configPath
	}
	return p, configPath, overrideIn, nil
}

func printCommandHelp(c *commands.CommandSchema) {
	fmt.Fprintf(os.Stdout, "%s - %s\n", c.Name, c.Short)
	if c.Help != "" {
		fmt.Fprintf(os.Stdout, "  %s\n", c.Help)
	}

	for _, f := range c.Flags {
		fmt.Fprintf(os.Stdout, "  -%s", f.Name)
		if !f.Bool {
			fmt.Fprintf(os.Stdout, " string")
		}
		fmt.Fprintf(os.Stdout, "\n    \t%s", f.Usage)
		if f.Default != "" && f.Default != "false" {
			fmt.Fprintf(os.Stdout, " (default %s)", f.Default)
		}
		fmt.Fprintln(os.Stdout)
	}
}
