//go:build android

package nebula

import (
	"net"

	"github.com/wlynxg/anet"
)

// anet relies on //go:linkname and so needs -ldflags=-checklinkname=0 on Go 1.23+. Nebula ships no
// Android binaries of its own, so that burden falls on consumers linking Android artifacts.

func init() {
	// anet only takes its bind-free path when it believes it is on API 30+, and detecting the running
	// device's level requires cgo. Pin it so a CGO_ENABLED=0 build cannot quietly fall back to the
	// denied path. The bind-free path is correct on older releases too, just unnecessary there.
	anet.SetAndroidVersion(11)
}

// The app sandbox denies bind() on netlink_route_socket, so the stdlib's RTM_GETLINK enumeration
// fails with EACCES and we advertise no underlay addresses at all. anet reads RTM_GETADDR from an
// unbound socket instead, so this must not be collapsed back into net.Interfaces.
func localInterfaces() ([]net.Interface, error) {
	return anet.Interfaces()
}

// net.Interface.Addrs goes back through the denied netlink path, so addresses have to come from anet
// as well. anet cannot report HardwareAddr, which localAddrs does not read.
func localInterfaceAddrs(i *net.Interface) ([]net.Addr, error) {
	return anet.InterfaceAddrsByInterface(i)
}
