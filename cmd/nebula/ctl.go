package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"syscall"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/diag"
)

// ctlMain implements `nebula ctl <command> [args...]`, which runs a debug command against the
// nebula already running on this host. Everything after the command name is forwarded to that
// nebula verbatim and parsed there by the same flag sets the ssh console uses, so this side
// deliberately understands as little as possible about it.
//
// Returns the process exit status.
func ctlMain(argv []string) int {
	fl := flag.NewFlagSet("nebula ctl", flag.ContinueOnError)
	fl.Usage = func() {
		out := fl.Output()
		fmt.Fprintf(out, "Usage: nebula ctl [-config path] [-socket path] <command> [arguments]\n\n")
		fmt.Fprintf(out, "Runs a debug command against the running nebula on this host, over its local\n")
		fmt.Fprintf(out, "control socket. Run `nebula ctl` with no command for the list of commands.\n\n")
		fl.PrintDefaults()
	}

	socket := fl.String("socket", "", "Path to the control socket. Overrides ctl.socket from the config")
	configPath := fl.String("config", "", "Path to the nebula config, read only to find ctl.socket")

	// The flag package stops at the first non-flag argument, which is exactly the behaviour
	// wanted here: `nebula ctl -socket /x list-hostmap -json` consumes -socket, stops at
	// list-hostmap, and leaves the rest untouched for the daemon to parse.
	if err := fl.Parse(argv); err != nil {
		// -h is a request, not a failure.
		if errors.Is(err, flag.ErrHelp) {
			return diag.StatusOK
		}
		return diag.StatusUsage
	}

	path := *socket
	if path == "" {
		path = ctlSocketPath(*configPath)
	}

	if path == "" {
		fmt.Fprintln(os.Stderr, "nebula ctl: no control socket path is known for this platform, set ctl.socket in the config")
		return diag.StatusError
	}

	client, err := diag.Dial(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, ctlDialError(path, err))
		return diag.StatusError
	}
	defer client.Close()

	args := fl.Args()
	status, err := client.Run(args, os.Stdout)
	if err != nil {
		if errors.Is(err, diag.ErrTruncated) {
			fmt.Fprintf(os.Stderr, "nebula ctl: nebula closed the connection before %s finished\n", ctlCommandName(args))
			return diag.StatusError
		}

		fmt.Fprintf(os.Stderr, "nebula ctl: %s\n", err)
		if status == diag.StatusOK {
			return diag.StatusError
		}
	}

	return status
}

// ctlSocketPath finds the socket to talk to. The platform default is the primary mechanism;
// reading the config is the refinement for someone who moved the socket. It is best effort by
// design, because config.DefaultPath resolves next to the nebula binary and a packaged install
// keeps its config somewhere else entirely, so a config we cannot find is the normal case
// rather than a failure.
func ctlSocketPath(configPath string) string {
	if configPath == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return diag.DefaultSocketPath()
		}
		configPath = p
	}

	c := config.NewC(slog.New(slog.DiscardHandler))
	if err := c.Load(configPath); err != nil {
		return diag.DefaultSocketPath()
	}

	return c.GetString("ctl.socket", diag.DefaultSocketPath())
}

// ctlDialError turns a connect failure into something an operator can act on. These messages
// are the entire user experience when things are not working, so they name the path and say
// what to check.
func ctlDialError(path string, err error) string {
	switch {
	case errors.Is(err, diag.ErrNotSupported):
		return "nebula ctl is not supported on this platform yet"

	case errors.Is(err, fs.ErrNotExist):
		return fmt.Sprintf("nebula ctl: no control socket at %s. Is nebula running? Is ctl.enabled set to false, or ctl.socket set to another path?", path)

	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Sprintf("nebula ctl: found a stale socket at %s, nebula is not listening on it", path)

	case errors.Is(err, fs.ErrPermission):
		return fmt.Sprintf("nebula ctl: permission denied opening %s. nebula ctl must run as the user nebula runs as, usually root", path)

	default:
		return fmt.Sprintf("nebula ctl: %s", err)
	}
}

// ctlCommandName names the command for an error message, for the case where there isn't one.
func ctlCommandName(args []string) string {
	if len(args) == 0 {
		return "the command"
	}

	return args[0]
}
