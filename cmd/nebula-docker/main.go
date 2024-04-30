package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/util"
	"golang.org/x/sys/unix"
)

// A version string that can be set with
//
//	-ldflags "-X main.Build=SOMEVERSION"
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

	err := os.MkdirAll("/dev/net", 0755)
	if err != nil {
		fmt.Printf("failed to mkdir -p /dev/net: %s", err)
		os.Exit(1)
	}
	s, err := os.Stat("/dev/net/tun")
	if err != nil || s.Mode().Type() != os.ModeCharDevice {
		err = unix.Mknod("/dev/net/tun", unix.S_IFCHR|0600, int(unix.Mkdev(10, 200)))
		if err != nil {
			fmt.Printf("failed to create /dev/net/tun: %s", err)
			os.Exit(1)
		}
	}

	c := config.NewC(l)
	err = c.Load(*configPath)
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
		ctrl.Start()
		ctrl.ShutdownBlock()
	}

	os.Exit(0)
}
