package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/port_forwarder"
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

	fwd_list := port_forwarder.NewPortForwardingList()
	disabled_tun := c.GetBool("tun.disabled", false)
	activate_service_anyway := c.GetBool("port_forwarding.enable_without_rules", false)
	if disabled_tun {
		port_forwarder.ParseConfig(l, c, fwd_list)
	}

	if !*configTest && disabled_tun && (activate_service_anyway || !fwd_list.IsEmpty()) {
		l.Infof("Configuring user-tun instead of disabled-tun as port forwarding is configured")

		control, err := nebula.Main(c, false, "custom-app", l, overlay.NewUserDeviceFromConfig)
		if err != nil {
			panic(err)
		}

		service, err := service.New(control)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to create service", err, l)
			os.Exit(1)
		}

		// initialize port forwarding:
		pf_service, err := port_forwarder.ConstructFromInitialFwdList(service, l, &fwd_list)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to start", err, l)
			os.Exit(1)
		}

		c.RegisterReloadCallback(func(c *config.C) {
			pf_service.ReloadConfigAndApplyChanges(c)
		})

		pf_service.Activate()

		// wait for termination request
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
		fmt.Println("Running, press ctrl+c to shutdown...")
		<-signalChannel

		// shutdown:
		service.CloseAndWait()

	} else {

		l.Info("Configuring for disabled or kernel tun. no port forwarding provided")
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
