package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/kardianos/service"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/logging"
)

var logger service.Logger

type program struct {
	configPath *string
	configTest *bool
	build      string
	control    *nebula.Control
}

func (p *program) Start(s service.Service) error {
	// Start should not block.
	logger.Info("Nebula service starting.")

	l := newPlatformLogger()

	c := config.NewC(l)
	err := c.Load(*p.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %s", err)
	}

	if err := logging.ApplyConfig(l, c); err != nil {
		return fmt.Errorf("failed to apply logging config: %s", err)
	}
	c.RegisterReloadCallback(func(c *config.C) {
		if err := logging.ApplyConfig(l, c); err != nil {
			l.Error("Failed to reconfigure logger on reload", "error", err)
		}
	})

	p.control, err = nebula.Main(c, *p.configTest, Build, l, nil)
	if err != nil {
		return err
	}

	p.control.Start()
	return nil
}

func (p *program) Stop(s service.Service) error {
	logger.Info("Nebula service stopping.")
	p.control.Stop()
	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func doService(configPath *string, configTest *bool, build string, serviceFlag *string) error {
	if *configPath == "" {
		ex, err := os.Executable()
		if err != nil {
			return err
		}
		*configPath = filepath.Dir(ex) + "/config.yaml"
		if !fileExists(*configPath) {
			*configPath = filepath.Dir(ex) + "/config.yml"
		}
	}

	svcConfig := &service.Config{
		Name:        "Nebula",
		DisplayName: "Nebula Network Service",
		Description: "Nebula network connectivity daemon for encrypted communications",
		Arguments:   []string{"-service", "run", "-config", *configPath},
	}

	prg := &program{
		configPath: configPath,
		configTest: configTest,
		build:      build,
	}

	// Here are what the different loggers are doing:
	// - `log` is the standard go log utility, meant to be used while the process is still attached to stdout/stderr
	// - `logger` is the service log utility that may be attached to a special place depending on OS (Windows will have it attached to the event log)
	// - in program.Start we build a *slog.Logger via newPlatformLogger; on non-Windows that is a stdout-backed slog logger, on Windows it routes records through the service logger
	s, err := service.New(prg, svcConfig)
	if err != nil {
		return err
	}

	errs := make(chan error, 5)
	logger, err = s.Logger(errs)
	if err != nil {
		return err
	}

	go func() {
		for {
			err := <-errs
			if err != nil {
				// Route any errors from the system logger to stdout as a best effort to notice issues there
				log.Print(err)
			}
		}
	}()

	switch *serviceFlag {
	case "run":
		if err := s.Run(); err != nil {
			// Route any errors to the system logger
			logger.Error(err)
		}
	default:
		if err := service.Control(s, *serviceFlag); err != nil {
			log.Printf("Valid actions: %q\n", service.ControlAction)
			return err
		}
	}

	return nil
}
