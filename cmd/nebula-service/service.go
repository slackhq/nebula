package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/kardianos/service"
	"github.com/slackhq/nebula"
)

var logger service.Logger

type program struct {
	exit       chan struct{}
	configPath *string
	configTest *bool
	build      string
}

func (p *program) Start(s service.Service) error {
	logger.Info("Nebula service starting.")
	p.exit = make(chan struct{})
	// Start should not block.
	go p.run()
	return nil
}

func (p *program) run() error {
	nebula.Main(*p.configPath, *p.configTest, Build, nil, nil)
	return nil
}

func (p *program) Stop(s service.Service) error {
	logger.Info("Nebula service stopping.")
	close(p.exit)
	return nil
}

func doService(configPath *string, configTest *bool, build string, serviceFlag *string) {

	if *configPath == "" {
		ex, err := os.Executable()
		if err != nil {
			panic(err)
		}
		*configPath = filepath.Dir(ex) + "/config.yaml"
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

	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	errs := make(chan error, 5)
	logger, err = s.Logger(errs)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			err := <-errs
			if err != nil {
				log.Print(err)
			}
		}
	}()

	switch *serviceFlag {
	case "run":
		err = s.Run()
		if err != nil {
			logger.Error(err)
		}
	default:
		err := service.Control(s, *serviceFlag)
		if err != nil {
			log.Printf("Valid actions: %q\n", service.ControlAction)
			log.Fatal(err)
		}
		return
	}

}
