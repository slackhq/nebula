package nebula

import (
	"fmt"
	"math"
	"net"
	"strconv"

	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
)

// This allows us to "guess" what the remote might be for a host while we wait
// for the lighthouse response. See "lighthouse.calculated_remotes" in the
// example config file.
type calculatedRemote struct {
	ipNet  net.IPNet
	maskIP iputil.VpnIp
	mask   iputil.VpnIp
	port   uint32
}

func newCalculatedRemote(ipNet *net.IPNet, port int) (*calculatedRemote, error) {
	// Ensure this is an IPv4 mask that we expect
	ones, bits := ipNet.Mask.Size()
	if ones == 0 || bits != 32 {
		return nil, fmt.Errorf("invalid mask: %v", ipNet)
	}
	if port < 0 || port > math.MaxUint16 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}

	return &calculatedRemote{
		ipNet:  *ipNet,
		maskIP: iputil.Ip2VpnIp(ipNet.IP),
		mask:   iputil.Ip2VpnIp(ipNet.Mask),
		port:   uint32(port),
	}, nil
}

func (c *calculatedRemote) String() string {
	return fmt.Sprintf("CalculatedRemote(mask=%v port=%d)", c.ipNet, c.port)
}

func (c *calculatedRemote) Apply(ip iputil.VpnIp) *Ip4AndPort {
	// Combine the masked bytes of the "mask" IP with the unmasked bytes
	// of the overlay IP
	masked := (c.maskIP & c.mask) | (ip & ^c.mask)

	return &Ip4AndPort{Ip: uint32(masked), Port: c.port}
}

func NewCalculatedRemotesFromConfig(c *config.C, k string) (*cidr.Tree4, error) {
	value := c.Get(k)
	if value == nil {
		return nil, nil
	}

	calculatedRemotes := cidr.NewTree4()

	rawMap, ok := value.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("config `%s` has invalid type: %T", k, value)
	}
	for rawKey, rawValue := range rawMap {
		rawCIDR, ok := rawKey.(string)
		if !ok {
			return nil, fmt.Errorf("config `%s` has invalid key (type %T): %v", k, rawKey, rawKey)
		}

		_, ipNet, err := net.ParseCIDR(rawCIDR)
		if err != nil {
			return nil, fmt.Errorf("config `%s` has invalid CIDR: %s", k, rawCIDR)
		}

		entry, err := newCalculatedRemotesListFromConfig(rawValue)
		if err != nil {
			return nil, fmt.Errorf("config '%s.%s': %w", k, rawCIDR, err)
		}

		calculatedRemotes.AddCIDR(ipNet, entry)
	}

	return calculatedRemotes, nil
}

func newCalculatedRemotesListFromConfig(raw any) ([]*calculatedRemote, error) {
	rawList, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("calculated_remotes entry has invalid type: %T", raw)
	}

	var l []*calculatedRemote
	for _, e := range rawList {
		c, err := newCalculatedRemotesEntryFromConfig(e)
		if err != nil {
			return nil, fmt.Errorf("calculated_remotes entry: %w", err)
		}
		l = append(l, c)
	}

	return l, nil
}

func newCalculatedRemotesEntryFromConfig(raw any) (*calculatedRemote, error) {
	rawMap, ok := raw.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("invalid type: %T", raw)
	}

	rawValue := rawMap["mask"]
	if rawValue == nil {
		return nil, fmt.Errorf("missing mask: %v", rawMap)
	}
	rawMask, ok := rawValue.(string)
	if !ok {
		return nil, fmt.Errorf("invalid mask (type %T): %v", rawValue, rawValue)
	}
	_, ipNet, err := net.ParseCIDR(rawMask)
	if err != nil {
		return nil, fmt.Errorf("invalid mask: %s", rawMask)
	}

	var port int
	rawValue = rawMap["port"]
	if rawValue == nil {
		return nil, fmt.Errorf("missing port: %v", rawMap)
	}
	switch v := rawValue.(type) {
	case int:
		port = v
	case string:
		port, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s: %w", v, err)
		}
	default:
		return nil, fmt.Errorf("invalid port (type %T): %v", rawValue, rawValue)
	}

	return newCalculatedRemote(ipNet, port)
}
