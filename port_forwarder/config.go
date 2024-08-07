package port_forwarder

import (
	"io"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
)

type ForwardConfig interface {
	SetupPortForwarding(tunService *service.Service, l *logrus.Logger) (io.Closer, error)
	ConfigDescriptor() string
}

type ConfigList interface {
	AddConfig(cfg ForwardConfig)
}

type ForwardConfigOutgoing struct {
	localListen   string
	remoteConnect string
}

type ForwardConfigIncoming struct {
	port                uint32
	forwardLocalAddress string
}
