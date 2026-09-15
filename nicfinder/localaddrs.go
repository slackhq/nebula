//go:build !android

package nicfinder

import (
	"errors"
	"fmt"
	"net"
)

// localInterfaces returns every interface with its addresses. An interface whose addresses cannot
// be read is left out and reported in the returned error alongside the rest.
func localInterfaces() ([]localInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate local interfaces: %w", err)
	}

	var errs []error
	out := make([]localInterface, 0, len(ifaces))
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get addresses for %s: %w", i.Name, err))
			continue
		}
		out = append(out, localInterface{Name: i.Name, Addrs: netipAddrs(addrs)})
	}
	return out, errors.Join(errs...)
}
