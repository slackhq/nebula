package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	port_forwarder "github.com/slackhq/nebula/port-forwarder"
	"github.com/slackhq/nebula/service"
	"github.com/slackhq/nebula/util"
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

	c := config.NewC(l)
	err := c.Load(*configPath)
	if err != nil {
		fmt.Printf("failed to load config: %s", err)
		os.Exit(1)
	}

	userspace_tun := c.GetBool("tun.user", false)
	if userspace_tun {
		l.Infof("Configuring userspace-tun instead of kernel tun")
		if *configTest {
			util.LogWithContextIfNeeded("Failed to start",
				errors.New("config test currently not supported for user-tun"), l)
			os.Exit(1)
		}

		service, err := service.New(c, l)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to start", err, l)
			os.Exit(1)
		}

		// initialize port forwarding:
		pf_service, err := port_forwarder.ConstructFromConfig(service, l, c)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to start", err, l)
			os.Exit(1)
		}
		pf_service.Activate()

		// wait for termination request
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
		fmt.Println("Running, press ctrl+c to shutdown...")
		<-signalChannel

		// shutdown:
		service.Close()
		if err := service.Wait(); err != nil {
			if errors.Is(err, os.ErrClosed) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, context.Canceled) {
				l.Debugf("Stop of user-tun service returned: %v", err)
			} else {
				util.LogWithContextIfNeeded("Unclean stop", err, l)
			}
		}

	} else {

		l.Infof("Configuring for kernel tun")
		ctrl, err := nebula.Main(c, *configTest, Build, l, nil)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to start", err, l)
			os.Exit(1)
		}

		if !*configTest {
			ctrl.Start()
			notifyReady(l)
			ctrl.ShutdownBlock()
		}
	}

	os.Exit(0)
}
