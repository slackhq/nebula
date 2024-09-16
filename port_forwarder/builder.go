package port_forwarder

import (
	"fmt"
	"io"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/service"
)

func ymlGetStringOfNode(node interface{}) string {
	return fmt.Sprintf("%v", node)
}

func ymlMapGetStringEntry(k string, m map[interface{}]interface{}) string {
	v, ok := m[k]
	if !ok {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

type ymlListNode = []interface{}
type ymlMapNode = map[interface{}]interface{}
type configFactoryFn = func(yml_node ymlMapNode) error
type configFactoryFnMap = map[string]configFactoryFn

type builderData struct {
	l         *logrus.Logger
	target    ConfigList
	factories map[string]configFactoryFnMap
}

func ParseConfig(
	l *logrus.Logger,
	c *config.C,
	target ConfigList,
) error {
	builder := builderData{
		l:         l,
		target:    target,
		factories: map[string]configFactoryFnMap{},
	}

	in := configFactoryFnMap{}
	in["udp"] = func(yml_node ymlMapNode) error {
		return builder.convertToForwardConfigIncoming(l, yml_node, false)
	}
	in["tcp"] = func(yml_node ymlMapNode) error {
		return builder.convertToForwardConfigIncoming(l, yml_node, true)
	}
	builder.factories["inbound"] = in

	out := configFactoryFnMap{}
	out["udp"] = func(yml_node ymlMapNode) error {
		return builder.convertToForwardConfigOutgoing(l, yml_node, false)
	}
	out["tcp"] = func(yml_node ymlMapNode) error {
		return builder.convertToForwardConfigOutgoing(l, yml_node, true)
	}
	builder.factories["outbound"] = out

	for _, direction := range [...]string{"inbound", "outbound"} {
		cfg_fwds := c.Get("port_forwarding." + direction)
		if cfg_fwds == nil {
			continue
		}

		cfg_fwds_list, ok := cfg_fwds.(ymlListNode)
		if !ok {
			return fmt.Errorf("yml node \"port_forwarding.%s\" needs to be a list", direction)
		}

		for fwd_idx, node := range cfg_fwds_list {
			node_map, ok := node.(ymlMapNode)
			if !ok {
				return fmt.Errorf("child yml node of \"port_forwarding.%s\" needs to be a map", direction)
			}

			protocols, ok := node_map["protocols"]
			if !ok {
				l.Infof("child yml node of \"port_forwarding.%s\" should have a child \"protocols\"", direction)
				continue
			}

			protocols_list, ok := protocols.(ymlListNode)
			if !ok {
				return fmt.Errorf("child yml node of \"port_forwarding.%s\" needs to have a child \"protocols\" that is a yml list", direction)
			}

			for _, proto := range protocols_list {
				proto_str := ymlGetStringOfNode(proto)
				factoryFn, ok := builder.factories[direction][proto_str]
				if !ok {
					return fmt.Errorf("child yml node of \"port_forwarding.%s.%d.protocols\" doesn't support: %s", direction, fwd_idx, proto_str)
				}

				err := factoryFn(node_map)
				if err != nil {
					return fmt.Errorf("child yml node of \"port_forwarding.%s.%d.protocols\" with proto %s - failed to instantiate forwarder: %v", direction, fwd_idx, proto_str, err)
				}
			}
		}
	}

	return nil
}

func ConstructFromInitialFwdList(
	tunService *service.Service,
	l *logrus.Logger,
	fwd_list *PortForwardingList,
) (*PortForwardingService, error) {

	pfService := &PortForwardingService{
		l:                     l,
		tunService:            tunService,
		configPortForwardings: fwd_list.configPortForwardings,
		portForwardings:       make(map[string]io.Closer),
	}

	return pfService, nil
}

func NewPortForwardingList() PortForwardingList {
	return PortForwardingList{
		configPortForwardings: map[string]ForwardConfig{},
	}
}

type PortForwardingList struct {
	configPortForwardings map[string]ForwardConfig
}

func (pfl PortForwardingList) AddConfig(cfg ForwardConfig) {
	pfl.configPortForwardings[cfg.ConfigDescriptor()] = cfg
}

func (pfl PortForwardingList) IsEmpty() bool {
	return len(pfl.configPortForwardings) == 0
}

func (s *PortForwardingService) ReloadConfigAndApplyChanges(
	c *config.C,
) error {

	s.l.Infof("reloading port forwarding configuration...")

	pflNew := NewPortForwardingList()

	err := ParseConfig(s.l, c, pflNew)
	if err != nil {
		return err
	}

	return s.ApplyChangesByNewFwdList(&pflNew)
}

func (s *PortForwardingService) ApplyChangesByNewFwdList(
	pflNew *PortForwardingList,
) error {

	to_be_closed := []string{}
	for old := range s.configPortForwardings {
		_, corresponding_new_exists := pflNew.configPortForwardings[old]
		if !corresponding_new_exists {
			to_be_closed = append(to_be_closed, old)
		}
	}

	s.CloseSelective(to_be_closed)

	to_be_added := map[string]ForwardConfig{}
	for new, cfg := range pflNew.configPortForwardings {
		_, corresponding_old_exists := s.configPortForwardings[new]
		if !corresponding_old_exists {
			to_be_added[cfg.ConfigDescriptor()] = cfg
		}
	}

	s.ActivateNew(to_be_added)

	return nil
}

func (builder *builderData) convertToForwardConfigOutgoing(
	_ *logrus.Logger,
	m ymlMapNode,
	isTcp bool,
) error {
	fwd_port := ForwardConfigOutgoing{
		localListen:   ymlMapGetStringEntry("listen_address", m),
		remoteConnect: ymlMapGetStringEntry("dial_address", m),
	}

	var cfg ForwardConfig
	if isTcp {
		cfg = ForwardConfigOutgoingTcp{fwd_port}
	} else {
		cfg = ForwardConfigOutgoingUdp{fwd_port}
	}

	builder.target.AddConfig(cfg)

	return nil
}

func (builder *builderData) convertToForwardConfigIncoming(
	_ *logrus.Logger,
	m ymlMapNode,
	isTcp bool,
) error {

	v, err := strconv.ParseUint(ymlMapGetStringEntry("listen_port", m), 10, 32)
	if err != nil {
		return err
	}

	fwd_port := ForwardConfigIncoming{
		port:                uint32(v),
		forwardLocalAddress: ymlMapGetStringEntry("dial_address", m),
	}

	var cfg ForwardConfig
	if isTcp {
		cfg = ForwardConfigIncomingTcp{fwd_port}
	} else {
		cfg = ForwardConfigIncomingUdp{fwd_port}
	}

	builder.target.AddConfig(cfg)

	return nil
}
