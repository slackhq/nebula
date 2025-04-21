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
//	-ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func main() {
	serviceFlag := flag.String("service", "", "Control the system service.")
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

	if *serviceFlag != "" {
		doService(configPath, configTest, Build, serviceFlag)
		os.Exit(1)
	}

	if *configPath == "" {
		fmt.Println("-config flag must be set")
		flag.Usage()
		os.Exit(1)
	}

	l := logrus.New()
	l.Out = os.Stdout

	c := config.NewC(l)
	err := c.Load(*configPath)
	if err != nil {
		fmt.Printf("failed to load config: %s", err)
		os.Exit(1)
	}

	ctrl, err := nebula.Main(c, *configTest, Build, l, nil)
	if err != nil {
		util.LogWithContextIfNeeded("Failed to start", err, l)
		os.Exit(1)
	}

	if !*configTest {
		wait, err := ctrl.Start()
		if err != nil {
			util.LogWithContextIfNeeded("Error while running", err, l)
			os.Exit(1)
		}

		go ctrl.ShutdownBlock()
		wait()

		l.Info("Goodbye")
	}

	os.Exit(0)
}
