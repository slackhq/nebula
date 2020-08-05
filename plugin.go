package nebula

import (
	"encoding/binary"
	"fmt"
	"plugin"
	"strconv"

	"golang.org/x/net/ipv4"
)

// The Plugin interface is provided to enable experimental features to implemented via go plugins.
// A plugin must export a symbol "P" that implements this interface.
type Plugin interface {
	Configure(config map[interface{}]interface{}) error
	Name() string
	Receive(b []byte) error
	Run(func(ip uint32, payload []byte))
}

func NewPluginsFromConfig(c *Config) (map[NebulaMessageSubType]Plugin, error) {
	conf := c.GetMapSlice("experimental.plugins", nil)
	if len(conf) == 0 {
		return nil, nil
	}

	token := c.GetString("experimental.privileged_plugins", "")
	accept := "I understand the risks and really want to allow plugins to run as root"
	allowPrivileged := token == accept

	root, err := privileged()
	if err != nil {
		return nil, fmt.Errorf("could not check admin privileges while loading plugins: %w", err)
	}
	if root && !allowPrivileged {
		return nil, fmt.Errorf("plugins disabled when running as a privileged account")
	}

	plugins := make(map[NebulaMessageSubType]Plugin)
	for _, m := range conf {
		var (
			id     uint8
			name   string
			path   string
			config map[interface{}]interface{}
		)
		for k, v := range m {
			switch fmt.Sprintf("%v", k) {
			case "name":
				name = fmt.Sprintf("%v", v)
			case "path":
				path = fmt.Sprintf("%v", v)
			case "id":
				s := fmt.Sprintf("%v", v)
				i, err := strconv.ParseUint(s, 10, 8)
				if err != nil {
					return nil, fmt.Errorf("%s is not a valid plugin type id", s)
				}
				id = uint8(i)
			case "config":
				c, ok := v.(map[interface{}]interface{})
				if !ok {
					return nil, fmt.Errorf("%s: config value should be a map when present", path)
				}
				config = c
			}
		}
		if path == "" || id == 0 {
			return nil, fmt.Errorf("invalid plugin config")
		}
		if name == "" {
			name = path
		}
		if _, ok := plugins[NebulaMessageSubType(id)]; ok {
			return nil, fmt.Errorf("duplicate plugin type id: %d", id)
		}
		p, err := loadPlugin(path)
		if err != nil {
			return nil, err
		}
		if len(config) > 0 {
			if err := p.Configure(config); err != nil {
				return nil, fmt.Errorf("%s: config failed: %w", path, err)
			}
		}
		plugins[NebulaMessageSubType(id)] = p

	}

	return plugins, nil
}

func loadPlugin(path string) (Plugin, error) {
	src, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not load plugin at %s: %w", path, err)
	}
	val, err := src.Lookup("P")
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}

	p, ok := val.(Plugin)
	if !ok {
		_ = val.(Plugin)
		return nil, fmt.Errorf("%s: nebula message plugin interface not implemented", path)
	}

	return p, nil
}

func (f *Interface) pluginSender(packetType NebulaMessageSubType) func(uint32, []byte) {
	return func(ip uint32, payload []byte) {
		hostinfo := f.getOrHandshake(ip)
		ci := hostinfo.ConnectionState

		length := ipv4.HeaderLen + len(payload)
		packet := make([]byte, length)
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(length))
		binary.BigEndian.PutUint32(packet[12:16], ip2int(f.inside.Cidr.IP.To4()))
		binary.BigEndian.PutUint32(packet[16:20], ip)
		copy(packet[ipv4.HeaderLen:], payload)

		nb := make([]byte, 12, 12)
		out := make([]byte, mtu)
		f.sendNoMetrics(message, NebulaMessageSubType(packetType), ci, hostinfo, hostinfo.remote, packet, nb, out)
	}
}
