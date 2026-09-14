//go:build !android

package nebula

import "net"

func localInterfaces() ([]localInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	out := make([]localInterface, len(ifaces))
	for n, i := range ifaces {
		out[n] = localInterface{Name: i.Name, Addrs: i.Addrs}
	}
	return out, nil
}
