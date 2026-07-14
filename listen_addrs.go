package nebula

import (
	"fmt"

	"github.com/slackhq/nebula/config"
)

// getListenAddrs reads a listener config value that may be either a single
// "host:port" string or a list of them, returning the addresses in order. A
// missing or empty value returns nil; blank entries in a list are skipped. This
// is what lets stats.listen and sshd.listen accept multiple bind addresses
// while remaining backwards compatible with a single string.
func getListenAddrs(c *config.C, key string) []string {
	switch v := c.Get(key).(type) {
	case nil:
		return nil
	case []any:
		addrs := make([]string, 0, len(v))
		for _, e := range v {
			if s := fmt.Sprintf("%v", e); s != "" {
				addrs = append(addrs, s)
			}
		}
		return addrs
	default:
		if s := fmt.Sprintf("%v", v); s != "" {
			return []string{s}
		}
		return nil
	}
}
