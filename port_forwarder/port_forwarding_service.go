package port_forwarder

import (
	"io"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
)

type PortForwardingService struct {
	l          *logrus.Logger
	tunService *service.Service

	configPortForwardings map[string]ForwardConfig
	portForwardings       map[string]io.Closer
}

func (t *PortForwardingService) AddConfig(cfg ForwardConfig) {
	t.configPortForwardings[cfg.ConfigDescriptor()] = cfg
}

func (t *PortForwardingService) Activate() error {
	return t.ActivateNew(t.configPortForwardings)
}

func (t *PortForwardingService) ActivateNew(newForwards map[string]ForwardConfig) error {

	for descriptor, config := range newForwards {
		fwd_instance, err := config.SetupPortForwarding(t.tunService, t.l)
		if err == nil {
			t.configPortForwardings[config.ConfigDescriptor()] = config
			t.portForwardings[config.ConfigDescriptor()] = fwd_instance
		} else {
			t.l.Errorf("failed to setup port forwarding #%s: %s", descriptor, config.ConfigDescriptor())
		}
	}

	return nil
}

func (t *PortForwardingService) CloseSelective(descriptors []string) error {

	for _, descriptor := range descriptors {
		delete(t.configPortForwardings, descriptor)
		pf, ok := t.portForwardings[descriptor]
		if ok {
			t.l.Infof("closing port forwarding: %s", descriptor)
			pf.Close()
			delete(t.portForwardings, descriptor)
		}
	}

	return nil
}

func (t *PortForwardingService) CloseAll() error {

	for descriptor, pf := range t.portForwardings {
		t.l.Infof("closing port forwarding: %s", descriptor)
		pf.Close()
		delete(t.portForwardings, descriptor)
	}

	return nil
}
