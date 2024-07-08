package nebula

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"

	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/config"
)

// This allows us to "guess" what the remote might be for a host while we wait
// for the lighthouse response. See "lighthouse.calculated_remotes" in the
// example config file.
type calculatedRemote struct {
	ipNet netip.Prefix
	mask  netip.Prefix
	port  uint32
}

func newCalculatedRemote(maskCidr netip.Prefix, port int) (*calculatedRemote, error) {
	masked := maskCidr.Masked()
	if port < 0 || port > math.MaxUint16 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}

	return &calculatedRemote{
		ipNet: maskCidr,
		mask:  masked,
		port:  uint32(port),
	}, nil
}

func (c *calculatedRemote) String() string {
	return fmt.Sprintf("CalculatedRemote(mask=%v port=%d)", c.ipNet, c.port)
}

func (c *calculatedRemote) Apply(ip netip.Addr) *Ip4AndPort {
	// Combine the masked bytes of the "mask" IP with the unmasked bytes
	// of the overlay IP
	if c.ipNet.Addr().Is4() {
		return c.apply4(ip)
	}
	return c.apply6(ip)
}

func (c *calculatedRemote) apply4(ip netip.Addr) *Ip4AndPort {
	//TODO: IPV6-WORK this can be less crappy
	maskb := net.CIDRMask(c.mask.Bits(), c.mask.Addr().BitLen())
	mask := binary.BigEndian.Uint32(maskb[:])

	b := c.mask.Addr().As4()
	maskIp := binary.BigEndian.Uint32(b[:])

	b = ip.As4()
	intIp := binary.BigEndian.Uint32(b[:])

	return &Ip4AndPort{(maskIp & mask) | (intIp & ^mask), c.port}
}

func (c *calculatedRemote) apply6(ip netip.Addr) *Ip4AndPort {
	//TODO: IPV6-WORK
	panic("Can not calculate ipv6 remote addresses")
}

func NewCalculatedRemotesFromConfig(c *config.C, k string) (*bart.Table[[]*calculatedRemote], error) {
	value := c.Get(k)
	if value == nil {
		return nil, nil
	}

	calculatedRemotes := new(bart.Table[[]*calculatedRemote])

	rawMap, ok := value.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("config `%s` has invalid type: %T", k, value)
	}
	for rawKey, rawValue := range rawMap {
		rawCIDR, ok := rawKey.(string)
		if !ok {
			return nil, fmt.Errorf("config `%s` has invalid key (type %T): %v", k, rawKey, rawKey)
		}

		cidr, err := netip.ParsePrefix(rawCIDR)
		if err != nil {
			return nil, fmt.Errorf("config `%s` has invalid CIDR: %s", k, rawCIDR)
		}

		//TODO: IPV6-WORK this does not verify that rawValue contains the same bits as cidr here
		entry, err := newCalculatedRemotesListFromConfig(rawValue)
		if err != nil {
			return nil, fmt.Errorf("config '%s.%s': %w", k, rawCIDR, err)
		}

		calculatedRemotes.Insert(cidr, entry)
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
	maskCidr, err := netip.ParsePrefix(rawMask)
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

	return newCalculatedRemote(maskCidr, port)
}
