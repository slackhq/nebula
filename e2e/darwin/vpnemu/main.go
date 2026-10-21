//go:build darwin

// vpnemu stands in for a macOS VPN app with an exit node in use, so route hijacks like the one
// Tailscale causes can be reproduced without Tailscale.
//
// A network extension does not touch the routing table itself. It hands its routes to
// nesessionmanager, which publishes them in configd's dynamic store under
// State:/Network/Service/<id>/IPv4 and /IPv6, and configd's IPMonitor installs them. vpnemu
// creates a utun and publishes the same keys directly, so configd does exactly what it would do
// for the real thing.
//
// Which routes it publishes follows Tailscale's rule for exit nodes
// (ipnlocal.internalAndExternalInterfacesFrom): every interface address prefix that is not a
// single IP counts as an attached LAN. With LAN access off those prefixes are claimed into the
// tunnel (-mode claim, published as AdditionalRoutes). With LAN access on they are excluded and
// leave through the next interface (-mode exclude, published as ExcludedRoutes on a service that
// overrides the primary).
//
// It runs until interrupted, then withdraws the service and closes its utun. Needs root.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

const (
	serviceID = "VPNEMU"
	// Tailscale's own addresses, single IPs, so the rule skips them like Tailscale skips its own
	addr4 = "100.100.0.1"
	addr6 = "fd7a:115c:a1e0::1"

	utunControlName = "com.apple.net.utun_control"
	utunOptIfname   = 2
	cfStringUTF8    = 0x08000100
)

var (
	cfStringCreateWithCString    func(alloc uintptr, s *byte, enc uint32) uintptr
	cfDataCreate                 func(alloc uintptr, b *byte, n int) uintptr
	cfPropertyListCreateWithData func(alloc, data uintptr, opts uint, format *int, err *uintptr) uintptr
	cfRelease                    func(ref uintptr)
	scDynamicStoreCreate         func(alloc, name, callout, ctx uintptr) uintptr
	scDynamicStoreSetValue       func(store, key, value uintptr) bool
	scDynamicStoreRemoveValue    func(store, key uintptr) bool
	scError                      func() int32
)

// loadFrameworks binds the few CoreFoundation and SystemConfiguration calls we need. purego does
// it without cgo, so this cross compiles and runs on a mac with no developer tools. JXA can read
// the dynamic store but its writes fail, and scutil cannot build the arrays of dictionaries the
// route keys hold.
func loadFrameworks() {
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		log.Fatal(err)
	}
	sc, err := purego.Dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		log.Fatal(err)
	}
	purego.RegisterLibFunc(&cfStringCreateWithCString, cf, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&cfDataCreate, cf, "CFDataCreate")
	purego.RegisterLibFunc(&cfPropertyListCreateWithData, cf, "CFPropertyListCreateWithData")
	purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")
	purego.RegisterLibFunc(&scDynamicStoreCreate, sc, "SCDynamicStoreCreate")
	purego.RegisterLibFunc(&scDynamicStoreSetValue, sc, "SCDynamicStoreSetValue")
	purego.RegisterLibFunc(&scDynamicStoreRemoveValue, sc, "SCDynamicStoreRemoveValue")
	purego.RegisterLibFunc(&scError, sc, "SCError")
}

func cfString(s string) uintptr {
	b := append([]byte(s), 0)
	return cfStringCreateWithCString(0, &b[0], cfStringUTF8)
}

// cfPlist builds a property list from its xml form, the least code way to make nested CF values
func cfPlist(xml string) uintptr {
	b := []byte(xml)
	d := cfDataCreate(0, &b[0], len(b))
	defer cfRelease(d)
	var errRef uintptr
	p := cfPropertyListCreateWithData(0, d, 0, nil, &errRef)
	if p == 0 {
		log.Fatalf("invalid property list:\n%s", xml)
	}
	return p
}

type store struct {
	ref    uintptr
	k4, k6 uintptr
}

func openStore() *store {
	return &store{
		ref: scDynamicStoreCreate(0, cfString("vpnemu"), 0, 0),
		k4:  cfString("State:/Network/Service/" + serviceID + "/IPv4"),
		k6:  cfString("State:/Network/Service/" + serviceID + "/IPv6"),
	}
}

func (s *store) set(key uintptr, xml string) {
	v := cfPlist(xml)
	defer cfRelease(v)
	if !scDynamicStoreSetValue(s.ref, key, v) {
		log.Fatalf("SCDynamicStoreSetValue failed: SCError %d", scError())
	}
}

func (s *store) withdraw() {
	scDynamicStoreRemoveValue(s.ref, s.k4)
	scDynamicStoreRemoveValue(s.ref, s.k6)
}

// createUtun opens a utun the kernel numbers for us and gives it Tailscale-like single addresses.
// The interface lives as long as the returned fd.
func createUtun() (int, string) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, unix.AF_SYS_CONTROL)
	if err != nil {
		log.Fatalf("system socket: %v", err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControlName)
	if err = unix.IoctlCtlInfo(fd, info); err != nil {
		log.Fatalf("CTLIOCGINFO: %v", err)
	}
	if err = unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		log.Fatalf("connect utun control: %v", err)
	}
	name, err := unix.GetsockoptString(fd, unix.AF_SYS_CONTROL, utunOptIfname)
	if err != nil {
		log.Fatalf("utun name: %v", err)
	}

	for _, args := range [][]string{
		{name, "inet", addr4, addr4, "netmask", "255.255.255.255", "up"},
		{name, "inet6", addr6, "prefixlen", "128"},
	} {
		if out, err := exec.Command("ifconfig", args...).CombinedOutput(); err != nil {
			log.Fatalf("ifconfig %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return fd, name
}

// lanPrefixes applies Tailscale's attached-LAN rule to every interface but those in skip
func lanPrefixes(skip []string) (v4, v6 []netip.Prefix) {
	ifs, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, i := range ifs {
		if slices.Contains(skip, i.Name) || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, _ := netip.AddrFromSlice(n.IP)
			ip = ip.Unmap()
			ones, _ := n.Mask.Size()
			pfx := netip.PrefixFrom(ip, ones).Masked()
			// Tailscale skips single IPs. Link-local is our addition, every interface has the
			// same fe80::/64 and claiming it would only break the harness's own host.
			if pfx.IsSingleIP() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.Is4() {
				v4 = append(v4, pfx)
			} else {
				v6 = append(v6, pfx)
			}
		}
	}
	slices.SortFunc(v4, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	slices.SortFunc(v6, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return v4, v6
}

func routes4(ps []netip.Prefix) string {
	var b strings.Builder
	for _, p := range ps {
		mask := net.IP(net.CIDRMask(p.Bits(), 32)).String()
		fmt.Fprintf(&b, "<dict><key>DestinationAddress</key><string>%s</string><key>SubnetMask</key><string>%s</string></dict>", p.Addr(), mask)
	}
	return b.String()
}

func routes6(ps []netip.Prefix) string {
	var b strings.Builder
	for _, p := range ps {
		fmt.Fprintf(&b, "<dict><key>DestinationAddress</key><string>%s</string><key>PrefixLength</key><integer>%d</integer></dict>", p.Addr(), p.Bits())
	}
	return b.String()
}

func (s *store) publish(ifName string, exclude bool, v4, v6 []netip.Prefix) {
	routesKey, primary := "AdditionalRoutes", ""
	if exclude {
		// configd only steers excluded routes for a service with a default route that is primary.
		// While this runs, everything not on a kept interface's subnet goes into the utun and dies.
		routesKey = "ExcludedRoutes"
		primary = "<key>Router</key><string>" + addr4 + "</string><key>OverridePrimary</key><integer>1</integer>"
	}

	const head = `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>`
	s.set(s.k4, head+
		"<key>InterfaceName</key><string>"+ifName+"</string>"+
		"<key>Addresses</key><array><string>"+addr4+"</string></array>"+
		"<key>SubnetMasks</key><array><string>255.255.255.255</string></array>"+primary+
		"<key>"+routesKey+"</key><array>"+routes4(v4)+"</array></dict></plist>")
	s.set(s.k6, head+
		"<key>InterfaceName</key><string>"+ifName+"</string>"+
		"<key>Addresses</key><array><string>"+addr6+"</string></array>"+
		"<key>PrefixLength</key><array><integer>128</integer></array>"+
		"<key>"+routesKey+"</key><array>"+routes6(v6)+"</array></dict></plist>")

	log.Printf("published %s on %s, %s: %v %v", serviceID, ifName, routesKey, v4, v6)
}

func main() {
	mode := flag.String("mode", "claim", "claim: exit node without LAN access, the prefixes are routed into the vpn\n"+
		"exclude: exit node with LAN access, the prefixes leave via the next interface and the vpn becomes primary")
	keep := flag.String("keep", "en0", "comma separated interfaces whose prefixes are never published, keep the one your ssh session uses")
	follow := flag.Bool("follow", true, "republish when interface prefixes change, as Tailscale does on link changes.\n"+
		"Off, a route stays published after its interface is gone, which is how a leftover route is staged")
	clear := flag.Bool("clear", false, "withdraw a service a crashed run left behind, then exit")
	flag.Parse()

	if *mode != "claim" && *mode != "exclude" {
		log.Fatalf("unknown -mode %q", *mode)
	}
	if os.Geteuid() != 0 {
		log.Fatal("needs root, to create the utun and write configd's dynamic store")
	}

	loadFrameworks()
	s := openStore()
	if *clear {
		s.withdraw()
		log.Print("withdrawn")
		return
	}

	fd, ifName := createUtun()
	exclude := *mode == "exclude"
	skip := append(strings.Split(*keep, ","), ifName)

	v4, v6 := lanPrefixes(skip)
	s.publish(ifName, exclude, v4, v6)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-sig:
			s.withdraw()
			_ = unix.Close(fd)
			log.Print("withdrawn")
			return
		case <-tick.C:
			if !*follow {
				continue
			}
			n4, n6 := lanPrefixes(skip)
			if !slices.Equal(n4, v4) || !slices.Equal(n6, v6) {
				v4, v6 = n4, n6
				s.publish(ifName, exclude, v4, v6)
			}
		}
	}
}
