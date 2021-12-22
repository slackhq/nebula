package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
)

// A version string that can be set with
//
//     -ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func main() {
	configPath := flag.String("config", "", "Path to either a file or directory to load configuration from")
	configTest := flag.Bool("test", false, "Test the config and print the end result. Non zero exit indicates a faulty config")
	printVersion := flag.Bool("version", false, "Print version")
	printUsage := flag.Bool("help", false, "Print command line usage")

	flag.Parse()

	if *printVersion {
		fmt.Printf("Version: %s\n", Build)
		os.Exit(0)
	}

	if *printUsage {
		flag.Usage()
		os.Exit(0)
	}

	if *configPath == "" {
		fmt.Println("-config flag must be set")
		flag.Usage()
		os.Exit(1)
	}

	l := logrus.New()
	l.Out = os.Stdout

	c := config.NewC(l)

	// read files from config path and store read files in configFiles string slice
	configFiles, err := config.ReadConfigFiles(*configPath)
	if err != nil {
		fmt.Printf("failed to read config(s): %s", err)
		os.Exit(1)
	}

	if err := c.Load(configFiles...); err != nil {
		fmt.Printf("failed to load config(s): %s", err)
		os.Exit(1)
	}

	// register SIGHUP handler
	c.RegisterSIGHUPHandler(func() error {
		// re-read files from config path
		configFiles, err := config.ReadConfigFiles(*configPath)
		if err != nil {
			return err
		}

		return c.ReloadConfig(configFiles...)
	})

	ctrl, err := nebula.Main(c, *configTest, Build, l, nil)
	switch v := err.(type) {
	case util.ContextualError:
		v.Log(l)
		os.Exit(1)
	case error:
		l.WithError(err).Error("Failed to start")
		os.Exit(1)
	}

	if !*configTest {
		ctrl.Start()
		ctrl.ShutdownBlock()
	}

	os.Exit(0)
}
