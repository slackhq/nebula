package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cmd/internal/ctl"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/localapi"
	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/util"
)

// A version string that can be set with
//
//	-ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func init() {
	if Build == "" {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}

		Build = strings.TrimPrefix(info.Main.Version, "v")
	}
}

func main() {
	// commands are either `nebula ctl ...` or `nebula -<flag> ...`
	if code, done := ctl.Subcommand(os.Args); done {
		os.Exit(code)
	}

	configPath := flag.String("config", "", "Path to either a file or directory to load configuration from")
	configTest := flag.Bool("test", false, "Test the config and print the end result. Non zero exit indicates a faulty config")
	printVersion := flag.Bool("version", false, "Print version")
	printUsage := flag.Bool("help", false, "Print command line usage")

	flag.Parse()

	// A word after the daemon's flags is `ctl` in the other place an operator puts it,
	// or a mistyped subcommand, and either way not a daemon to start; see Trailing.
	if code, done := ctl.Trailing(flag.Args(), *configPath); done {
		os.Exit(code)
	}

	if *printVersion {
		fmt.Printf("Version: %s\n", Build)
		os.Exit(0)
	}

	if *printUsage {
		flag.Usage()
		os.Exit(0)
	}

	if *configPath == "" {
		p, err := config.DefaultPath()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		*configPath = p
	}

	l := logging.NewLogger(os.Stdout)

	c := config.NewC(l)
	err := c.Load(*configPath)
	if err != nil {
		fmt.Printf("failed to load config: %s", err)
		os.Exit(1)
	}

	if err := logging.ApplyConfig(l, c); err != nil {
		fmt.Printf("failed to apply logging config: %s", err)
		os.Exit(1)
	}
	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		if err := logging.ApplyConfig(l, c); err != nil {
			l.Error("Failed to reconfigure logger on reload", "error", err)
			r.Failed()
		}
	})

	ctrl, err := nebula.Main(c, *configTest, Build, l, nil)
	if err != nil {
		util.LogWithContextIfNeeded("Failed to start", err, l)
		os.Exit(1)
	}

	if !*configTest {
		if err := ctrl.Start(); err != nil {
			util.LogWithContextIfNeeded("Error while running", err, l)
			os.Exit(1)
		}

		ctl := localapi.Wire(ctrl.Context(), l, c, ctrl.Commands())

		go ctrl.ShutdownBlock()
		notifyReady(l)

		err := ctrl.Wait()

		// os.Exit skips deferred calls, so the sockets are removed here, before either
		// exit below, rather than left to a deferred Stop that would never run.
		ctl.Stop()

		if err != nil {
			l.Error("Nebula stopped due to fatal error", "error", err)
			os.Exit(2)
		}

		l.Info("Goodbye")
	}

	os.Exit(0)
}
