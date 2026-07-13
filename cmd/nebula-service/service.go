package main

import (
	"fmt"
	"log"
	"os"

	"github.com/kardianos/service"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/logging"
)

var logger service.Logger

type program struct {
	configPath *string
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

	p.control, err = nebula.Main(c, false, Build, l, nil)
	if err != nil {
		return err
	}

	wait, err := p.control.Start()
	if err != nil {
		return err
	}

	// Nebula can stop itself on a fatal packet reader error, make sure to log it if it happens.
	go func() {
		if err := wait(); err != nil {
			logger.Error(fmt.Sprintf("Nebula stopped due to fatal error: %v", err))
			os.Exit(2)
		}
	}()

	return nil
}

func (p *program) Stop(s service.Service) error {
	logger.Info("Nebula service stopping.")
	if p.control == nil {
		return nil
	}

	p.control.Stop()

	// block until nebula has fully drained before reporting stopped.
	// error logging is handled by Start.
	_ = p.control.Wait()
	return nil
}

func doService(configPath *string, build string, serviceFlag *string) error {
	if *configPath == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return err
		}
		*configPath = p
	}

	svcConfig := &service.Config{
		Name:        "Nebula",
		DisplayName: "Nebula Network Service",
		Description: "Nebula network connectivity daemon for encrypted communications",
		Arguments:   []string{"-service", "run", "-config", *configPath},
	}

	prg := &program{
		configPath: configPath,
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
			// Route any errors to the system logger and report the failure
			logger.Error(err)
			return err
		}
	default:
		if err := service.Control(s, *serviceFlag); err != nil {
			log.Printf("Valid actions: %q\n", service.ControlAction)
			return err
		}
	}

	return nil
}
