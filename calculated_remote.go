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

func newCalculatedRemote(cidr, maskCidr netip.Prefix, port int) (*calculatedRemote, error) {
	if maskCidr.Addr().BitLen() != cidr.Addr().BitLen() {
		return nil, fmt.Errorf("invalid mask: %s for cidr: %s", maskCidr, cidr)
	}

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

func (c *calculatedRemote) ApplyV4(addr netip.Addr) *V4AddrPort {
	// Combine the masked bytes of the "mask" IP with the unmasked bytes of the overlay IP
	maskb := net.CIDRMask(c.mask.Bits(), c.mask.Addr().BitLen())
	mask := binary.BigEndian.Uint32(maskb[:])

	b := c.mask.Addr().As4()
	maskAddr := binary.BigEndian.Uint32(b[:])

	b = addr.As4()
	intAddr := binary.BigEndian.Uint32(b[:])

	return &V4AddrPort{(maskAddr & mask) | (intAddr & ^mask), c.port}
}

func (c *calculatedRemote) ApplyV6(addr netip.Addr) *V6AddrPort {
	mask := net.CIDRMask(c.mask.Bits(), c.mask.Addr().BitLen())
	maskAddr := c.mask.Addr().As16()
	calcAddr := addr.As16()

	ap := V6AddrPort{Port: c.port}

	maskb := binary.BigEndian.Uint64(mask[:8])
	maskAddrb := binary.BigEndian.Uint64(maskAddr[:8])
	calcAddrb := binary.BigEndian.Uint64(calcAddr[:8])
	ap.Hi = (maskAddrb & maskb) | (calcAddrb & ^maskb)

	maskb = binary.BigEndian.Uint64(mask[8:])
	maskAddrb = binary.BigEndian.Uint64(maskAddr[8:])
	calcAddrb = binary.BigEndian.Uint64(calcAddr[8:])
	ap.Lo = (maskAddrb & maskb) | (calcAddrb & ^maskb)

	return &ap
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

		entry, err := newCalculatedRemotesListFromConfig(cidr, rawValue)
		if err != nil {
			return nil, fmt.Errorf("config '%s.%s': %w", k, rawCIDR, err)
		}

		calculatedRemotes.Insert(cidr, entry)
	}

	return calculatedRemotes, nil
}

func newCalculatedRemotesListFromConfig(cidr netip.Prefix, raw any) ([]*calculatedRemote, error) {
	rawList, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("calculated_remotes entry has invalid type: %T", raw)
	}

	var l []*calculatedRemote
	for _, e := range rawList {
		c, err := newCalculatedRemotesEntryFromConfig(cidr, e)
		if err != nil {
			return nil, fmt.Errorf("calculated_remotes entry: %w", err)
		}
		l = append(l, c)
	}

	return l, nil
}

func newCalculatedRemotesEntryFromConfig(cidr netip.Prefix, raw any) (*calculatedRemote, error) {
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

	return newCalculatedRemote(cidr, maskCidr, port)
}
