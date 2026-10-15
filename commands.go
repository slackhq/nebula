package nebula

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"sort"
	"strings"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/logging"
)

// The commands nebula serves. attachCommands builds the one registry every surface
// reads. See the commands package for what a Command is.

type sshListHostMapFlags struct {
	Json    bool
	Pretty  bool
	ByIndex bool
}

type sshPrintCertFlags struct {
	Json   bool
	Pretty bool
	Raw    bool
}

type sshPrintTunnelFlags struct {
	Pretty bool
}

type sshChangeRemoteFlags struct {
	Address string
}

type sshCloseTunnelFlags struct {
	LocalOnly bool
}

type sshCreateTunnelFlags struct {
	Address string
}

type sshDeviceInfoFlags struct {
	Json   bool
	Pretty bool
}

func attachCommands(l *slog.Logger, c *config.C, reg *commands.Registry, f *Interface) {
	reg.Register(&commands.Command{
		Name:             commands.ListHostmap,
		ShortDescription: "List all known previously connected hosts",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshListHostMap(f.hostMap, fs, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.ListPendingHostmap,
		ShortDescription: "List all handshaking hosts",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshListHostMap(f.handshakeManager, fs, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.ListLighthouseAddrmap,
		ShortDescription: "List all lighthouse map entries",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshListLighthouseMap(f.lightHouse, fs, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.Reload,
		ShortDescription: "Reloads configuration from disk, same as sending HUP to the process",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshReload(l, c, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.LogLevel,
		ShortDescription: "Gets or sets the current log level",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshLogLevel(l, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.LogFormat,
		ShortDescription: "Gets or sets the current log format",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshLogFormat(l, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.Version,
		ShortDescription: "Prints the currently running version of nebula",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshVersion(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.DeviceInfo,
		ShortDescription: "Prints information about the network device.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshDeviceInfoFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshDeviceInfo(f, fs, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.PrintCert,
		ShortDescription: "Prints the current certificate being used or the certificate for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintCertFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.Raw, "raw", false, "raw prints the PEM encoded certificate, not compatible with -json or -pretty")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshPrintCert(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.PrintTunnel,
		ShortDescription: "Prints json details about a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshPrintTunnel(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.PrintRelays,
		ShortDescription: "Prints json details about all relay info",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshPrintRelays(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.ChangeRemote,
		ShortDescription: "Changes the remote address used in the tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshChangeRemoteFlags{}
			fl.StringVar(&s.Address, "address", "", "The new remote address, ip:port")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshChangeRemote(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.CloseTunnel,
		ShortDescription: "Closes a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshCloseTunnelFlags{}
			fl.BoolVar(&s.LocalOnly, "local-only", false, "Disables notifying the remote that the tunnel is shutting down")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshCloseTunnel(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.CreateTunnel,
		ShortDescription: "Creates a tunnel for the provided vpn address",
		Help:             "The lighthouses will be queried for real addresses but you can provide one as well.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshCreateTunnelFlags{}
			fl.StringVar(&s.Address, "address", "", "Optionally provide a real remote address, ip:port ")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshCreateTunnel(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.QueryLighthouse,
		ShortDescription: "Query the lighthouses for the provided vpn address",
		Help:             "This command is asynchronous. Only currently known udp addresses will be printed.",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return sshQueryLighthouse(f, fs, a, w)
		},
	})
}

func sshListHostMap(hl controlHostLister, a any, w commands.StringWriter) error {
	fs, ok := a.(*sshListHostMapFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *sshListHostMapFlags but was %T", a)
	}

	var hm []ControlHostInfo
	if fs.ByIndex {
		hm = listHostMapIndexes(hl)
	} else {
		hm = listHostMapHosts(hl)
	}

	sort.Slice(hm, func(i, j int) bool {
		return hm[i].VpnAddrs[0].Compare(hm[j].VpnAddrs[0]) < 0
	})

	if fs.Json || fs.Pretty {
		js := json.NewEncoder(w.GetWriter())
		if fs.Pretty {
			js.SetIndent("", "    ")
		}

		if err := js.Encode(hm); err != nil {
			return err
		}

	} else {
		for _, v := range hm {
			err := w.WriteLine(fmt.Sprintf("%s: %s", v.VpnAddrs, v.RemoteAddrs))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func sshListLighthouseMap(lightHouse *LightHouse, a any, w commands.StringWriter) error {
	fs, ok := a.(*sshListHostMapFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *sshListHostMapFlags but was %T", a)
	}

	type lighthouseInfo struct {
		VpnAddr string    `json:"vpnAddr"`
		Addrs   *CacheMap `json:"addrs"`
	}

	lightHouse.RLock()
	addrMap := make([]lighthouseInfo, len(lightHouse.addrMap))
	x := 0
	for k, v := range lightHouse.addrMap {
		addrMap[x] = lighthouseInfo{
			VpnAddr: k.String(),
			Addrs:   v.CopyCache(),
		}
		x++
	}
	lightHouse.RUnlock()

	sort.Slice(addrMap, func(i, j int) bool {
		return strings.Compare(addrMap[i].VpnAddr, addrMap[j].VpnAddr) < 0
	})

	if fs.Json || fs.Pretty {
		js := json.NewEncoder(w.GetWriter())
		if fs.Pretty {
			js.SetIndent("", "    ")
		}

		if err := js.Encode(addrMap); err != nil {
			return err
		}

	} else {
		for _, v := range addrMap {
			b, err := json.Marshal(v.Addrs)
			if err != nil {
				return err
			}
			err = w.WriteLine(fmt.Sprintf("%s: %s", v.VpnAddr, string(b)))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func sshVersion(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	return w.WriteLine(fmt.Sprintf("%s", ifce.version))
}

func sshQueryLighthouse(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	if len(a) == 0 {
		return commands.Fail(w, "No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return commands.Fail(w, fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return commands.Fail(w, fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	var cm *CacheMap
	rl := ifce.lightHouse.Query(vpnAddr)
	if rl != nil {
		cm = rl.CopyCache()
	}
	return json.NewEncoder(w.GetWriter()).Encode(cm)
}

func sshCloseTunnel(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	flags, ok := fs.(*sshCloseTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *sshCloseTunnelFlags but was %T", fs)
	}

	if len(a) == 0 {
		return commands.Fail(w, "No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return commands.Fail(w, fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return commands.Fail(w, fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return commands.Fail(w, fmt.Sprintf("Could not find tunnel for vpn address: %v", a[0]))
	}

	if !flags.LocalOnly {
		ifce.send(
			header.CloseTunnel,
			0,
			hostInfo.ConnectionState,
			hostInfo,
			[]byte{},
			make([]byte, 12, 12),
			make([]byte, mtu),
		)
	}

	ifce.closeTunnel(hostInfo)
	return w.WriteLine("Closed")
}

func sshCreateTunnel(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	flags, ok := fs.(*sshCreateTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *sshCreateTunnelFlags but was %T", fs)
	}

	if len(a) == 0 {
		return commands.Fail(w, "No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return commands.Fail(w, fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return commands.Fail(w, fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo != nil {
		return commands.Fail(w, fmt.Sprintf("Tunnel already exists"))
	}

	hostInfo = ifce.handshakeManager.QueryVpnAddr(vpnAddr)
	if hostInfo != nil {
		return commands.Fail(w, fmt.Sprintf("Tunnel already handshaking"))
	}

	var addr netip.AddrPort
	if flags.Address != "" {
		addr, err = netip.ParseAddrPort(flags.Address)
		if err != nil {
			return commands.Fail(w, "Address could not be parsed")
		}
	}

	// Set the remote from the callback, which StartHandshake runs under the handshake manager lock
	// before the hostinfo reaches the handshake loop or the static-host trigger, so the address is
	// in the RemoteList before the first handshake is sent.
	ifce.handshakeManager.StartHandshake(vpnAddr, func(hh *HandshakeHostInfo) {
		if addr.IsValid() {
			hh.hostinfo.SetRemote(addr)
		}
	})

	return w.WriteLine("Created")
}

func sshChangeRemote(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	flags, ok := fs.(*sshChangeRemoteFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *sshChangeRemoteFlags but was %T", fs)
	}

	if len(a) == 0 {
		return commands.Fail(w, "No vpn address was provided")
	}

	if flags.Address == "" {
		return commands.Fail(w, "No address was provided")
	}

	addr, err := netip.ParseAddrPort(flags.Address)
	if err != nil {
		return commands.Fail(w, "Address could not be parsed")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return commands.Fail(w, fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return commands.Fail(w, fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return commands.Fail(w, fmt.Sprintf("Could not find tunnel for vpn address: %v", a[0]))
	}

	hostInfo.SetRemote(addr)
	return w.WriteLine("Changed")
}

func sshLogLevel(l *slog.Logger, fs any, a []string, w commands.StringWriter) error {
	ctrl, ok := l.Handler().(interface {
		GetLevel() slog.Level
		SetLevel(slog.Level)
	})
	if !ok {
		return commands.Fail(w, "Log level is not reconfigurable on this logger")
	}

	if len(a) == 0 {
		return w.WriteLine(fmt.Sprintf("Log level is: %s", logging.LevelName(ctrl.GetLevel())))
	}

	level, err := logging.ParseLevel(strings.ToLower(a[0]))
	if err != nil {
		return commands.Fail(w, fmt.Sprintf("Unknown log level %s. Possible log levels: trace, debug, info, warn, error", a))
	}

	ctrl.SetLevel(level)
	return w.WriteLine(fmt.Sprintf("Log level is: %s", logging.LevelName(ctrl.GetLevel())))
}

func sshLogFormat(l *slog.Logger, fs any, a []string, w commands.StringWriter) error {
	ctrl, ok := l.Handler().(interface {
		GetFormat() string
		SetFormat(string) error
	})
	if !ok {
		return commands.Fail(w, "Log format is not reconfigurable on this logger")
	}

	if len(a) == 0 {
		return w.WriteLine(fmt.Sprintf("Log format is: %s", ctrl.GetFormat()))
	}

	if err := ctrl.SetFormat(strings.ToLower(a[0])); err != nil {
		return commands.Fail(w, fmt.Sprintf("Unable to set log format: %s", err))
	}
	return w.WriteLine(fmt.Sprintf("Log format is: %s", ctrl.GetFormat()))
}

func sshPrintCert(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	args, ok := fs.(*sshPrintCertFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *sshPrintCertFlags but was %T", fs)
	}

	cert := ifce.pki.getCertState().GetDefaultCertificate()
	if len(a) > 0 {
		vpnAddr, err := netip.ParseAddr(a[0])
		if err != nil {
			return commands.Fail(w, fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
		}

		if !vpnAddr.IsValid() {
			return commands.Fail(w, fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
		}

		hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
		if hostInfo == nil {
			return commands.Fail(w, fmt.Sprintf("Could not find tunnel for vpn addr: %v", a[0]))
		}

		cert = hostInfo.GetCert().Certificate
	}

	if args.Json || args.Pretty {
		b, err := cert.MarshalJSON()
		if err != nil {
			return commands.Fail(w, fmt.Sprintf("Unable to marshal the certificate: %s", err))
		}

		if args.Pretty {
			buf := new(bytes.Buffer)
			if err := json.Indent(buf, b, "", "    "); err != nil {
				return commands.Fail(w, fmt.Sprintf("Unable to marshal the certificate: %s", err))
			}
			b = buf.Bytes()
		}

		return w.WriteBytes(b)
	}

	if args.Raw {
		b, err := cert.MarshalPEM()
		if err != nil {
			return commands.Fail(w, fmt.Sprintf("Unable to marshal the certificate: %s", err))
		}

		return w.WriteBytes(b)
	}

	return w.WriteLine(cert.String())
}

func sshPrintRelays(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	args, ok := fs.(*sshPrintTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *sshPrintTunnelFlags but was %T", fs)
	}

	relays := map[uint32]*HostInfo{}
	ifce.hostMap.Lock()
	maps.Copy(relays, ifce.hostMap.Relays)
	ifce.hostMap.Unlock()

	type RelayFor struct {
		Error          string `json:",omitempty"`
		Type           string
		State          string
		PeerAddr       netip.Addr
		LocalIndex     uint32
		RemoteIndex    uint32
		RelayedThrough []netip.Addr
	}

	type RelayOutput struct {
		NebulaAddr    netip.Addr
		RelayForAddrs []RelayFor
	}

	type CmdOutput struct {
		Relays []*RelayOutput
	}

	co := CmdOutput{}

	enc := json.NewEncoder(w.GetWriter())

	if args.Pretty {
		enc.SetIndent("", "    ")
	}

	for k, v := range relays {
		ro := RelayOutput{NebulaAddr: v.vpnAddrs[0]}
		co.Relays = append(co.Relays, &ro)
		relayHI := ifce.hostMap.QueryVpnAddr(v.vpnAddrs[0])
		if relayHI == nil {
			ro.RelayForAddrs = append(ro.RelayForAddrs, RelayFor{Error: "could not find hostinfo"})
			continue
		}
		for _, vpnAddr := range relayHI.relayState.CopyRelayForIps() {
			rf := RelayFor{}
			r, ok := relayHI.relayState.GetRelayForByAddr(vpnAddr)
			if ok {
				t := ""
				switch r.Type {
				case ForwardingType:
					t = "forwarding"
				case TerminalType:
					t = "terminal"
				default:
					t = "unknown"
				}

				s := ""
				switch r.State {
				case Requested:
					s = "requested"
				case Established:
					s = "established"
				default:
					s = "unknown"
				}

				rf.LocalIndex = r.LocalIndex
				rf.RemoteIndex = r.RemoteIndex
				rf.PeerAddr = r.PeerAddr
				rf.Type = t
				rf.State = s
				if rf.LocalIndex != k {
					rf.Error = fmt.Sprintf("hostmap LocalIndex '%v' does not match RelayState LocalIndex", k)
				}
			}
			relayedHI := ifce.hostMap.QueryVpnAddr(vpnAddr)
			if relayedHI != nil {
				rf.RelayedThrough = append(rf.RelayedThrough, relayedHI.relayState.CopyRelayIps()...)
			}

			ro.RelayForAddrs = append(ro.RelayForAddrs, rf)
		}
	}
	err := enc.Encode(co)
	if err != nil {
		return err
	}
	return nil
}

func sshPrintTunnel(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	args, ok := fs.(*sshPrintTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *sshPrintTunnelFlags but was %T", fs)
	}

	if len(a) == 0 {
		return commands.Fail(w, "No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return commands.Fail(w, fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return commands.Fail(w, fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return commands.Fail(w, fmt.Sprintf("Could not find tunnel for vpn addr: %v", a[0]))
	}

	enc := json.NewEncoder(w.GetWriter())
	if args.Pretty {
		enc.SetIndent("", "    ")
	}

	return enc.Encode(copyHostInfo(hostInfo, ifce.hostMap.GetPreferredRanges()))
}

func sshDeviceInfo(ifce *Interface, fs any, w commands.StringWriter) error {

	data := struct {
		Name string         `json:"name"`
		Cidr []netip.Prefix `json:"cidr"`
	}{
		Name: ifce.inside.Name(),
		Cidr: make([]netip.Prefix, len(ifce.inside.Networks())),
	}

	copy(data.Cidr, ifce.inside.Networks())

	flags, ok := fs.(*sshDeviceInfoFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be sshDeviceInfoFlags but was %+v", fs)
	}

	if flags.Json || flags.Pretty {
		js := json.NewEncoder(w.GetWriter())
		if flags.Pretty {
			js.SetIndent("", "    ")
		}

		return js.Encode(data)
	} else {
		return w.WriteLine(fmt.Sprintf("name=%v cidr=%v", data.Name, data.Cidr))
	}
}

// sshReload reloads the config and writes the result to the client. It reloads even if the client has gone away
func sshReload(l *slog.Logger, c *config.C, w commands.StringWriter) error {
	writeErr := w.WriteLine("Reloading config")
	res := c.ReloadConfig()
	res.Log(l)
	if err := w.WriteLine(res.String()); writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		return writeErr
	}
	if res.Err != nil || res.Failed {
		return &commands.Failure{Msg: res.String()}
	}
	return nil
}
