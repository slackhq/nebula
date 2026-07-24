//go:build !android

package nebula

import "net"

func localInterfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

func localInterfaceAddrs(i *net.Interface) ([]net.Addr, error) {
	return i.Addrs()
}
