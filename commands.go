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
	"github.com/slackhq/nebula/logging"
)

// The commands nebula serves. attachCommands builds the one registry every surface
// reads. See the commands package for what a Command is.

type listHostMapFlags struct {
	Json    bool
	Pretty  bool
	ByIndex bool
}

// listHostMapFlagSet is the flag set list-hostmap and list-pending-hostmap share.
func listHostMapFlagSet() (*flag.FlagSet, any) {
	fl := flag.NewFlagSet("", flag.ContinueOnError)
	s := listHostMapFlags{}
	fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
	fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
	fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
	return fl, &s
}

type printCertFlags struct {
	Json   bool
	Pretty bool
	Raw    bool
}

type printTunnelFlags struct {
	Pretty bool
}

type changeRemoteFlags struct {
	Address string
}

type closeTunnelFlags struct {
	LocalOnly bool
}

type createTunnelFlags struct {
	Address string
}

type deviceInfoFlags struct {
	Json   bool
	Pretty bool
}

func attachCommands(l *slog.Logger, c *config.C, reg *commands.Registry, f *Interface) {
	reg.Register(&commands.Command{
		Name:             commands.ListHostmap,
		ShortDescription: "List all known previously connected hosts",
		Flags:            listHostMapFlagSet,
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return listHostMapCommand(f.hostMap, fs, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.ListPendingHostmap,
		ShortDescription: "List all handshaking hosts",
		Flags:            listHostMapFlagSet,
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return listHostMapCommand(f.handshakeManager, fs, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.ListLighthouseAddrmap,
		ShortDescription: "List all lighthouse map entries",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := listHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return listLighthouseAddrmapCommand(f.lightHouse, fs, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.Reload,
		ShortDescription: "Reloads configuration from disk, same as sending HUP to the process",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return reloadCommand(l, c, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.LogLevel,
		ShortDescription: "Gets or sets the current log level",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return logLevelCommand(l, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.LogFormat,
		ShortDescription: "Gets or sets the current log format",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return logFormatCommand(l, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.Version,
		ShortDescription: "Prints the currently running version of nebula",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return versionCommand(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.DeviceInfo,
		ShortDescription: "Prints information about the network device.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := deviceInfoFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return deviceInfoCommand(f, fs, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.PrintCert,
		ShortDescription: "Prints the current certificate being used or the certificate for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := printCertFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.Raw, "raw", false, "raw prints the PEM encoded certificate, not compatible with -json or -pretty")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return printCertCommand(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.PrintTunnel,
		ShortDescription: "Prints json details about a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := printTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return printTunnelCommand(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.PrintRelays,
		ShortDescription: "Prints json details about all relay info",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := printTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return printRelaysCommand(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.ChangeRemote,
		ShortDescription: "Changes the remote address used in the tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := changeRemoteFlags{}
			fl.StringVar(&s.Address, "address", "", "The new remote address, ip:port")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return changeRemoteCommand(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.CloseTunnel,
		ShortDescription: "Closes a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := closeTunnelFlags{}
			fl.BoolVar(&s.LocalOnly, "local-only", false, "Disables notifying the remote that the tunnel is shutting down")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return closeTunnelCommand(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.CreateTunnel,
		ShortDescription: "Creates a tunnel for the provided vpn address",
		Help:             "The lighthouses will be queried for real addresses but you can provide one as well.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := createTunnelFlags{}
			fl.StringVar(&s.Address, "address", "", "Optionally provide a real remote address, ip:port ")
			return fl, &s
		},
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return createTunnelCommand(f, fs, a, w)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.QueryLighthouse,
		ShortDescription: "Query the lighthouses for the provided vpn address",
		Help:             "This command is asynchronous. Only currently known udp addresses will be printed.",
		Callback: func(fs any, a []string, w commands.StringWriter) error {
			return queryLighthouseCommand(f, fs, a, w)
		},
	})
}

func listHostMapCommand(hl controlHostLister, a any, w commands.StringWriter) error {
	fs, ok := a.(*listHostMapFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *listHostMapFlags but was %T", a)
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

func listLighthouseAddrmapCommand(lightHouse *LightHouse, a any, w commands.StringWriter) error {
	fs, ok := a.(*listHostMapFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *listHostMapFlags but was %T", a)
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

// parseVpnAddr parses the vpn address a command takes as its first operand, failing to w
// when there is none or it does not parse. noun is how the command's messages name it,
// "vpn address" or "vpn addr", which the output golden pins per command.
func parseVpnAddr(a []string, noun string, w commands.StringWriter) (netip.Addr, error) {
	if len(a) == 0 {
		return netip.Addr{}, commands.Fail(w, "No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return netip.Addr{}, commands.Fail(w, fmt.Sprintf("The provided %s could not be parsed: %s", noun, a[0]))
	}

	return vpnAddr, nil
}

func versionCommand(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	return w.WriteLine(ifce.version)
}

func queryLighthouseCommand(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	vpnAddr, err := parseVpnAddr(a, "vpn address", w)
	if err != nil {
		return err
	}

	var cm *CacheMap
	rl := ifce.lightHouse.Query(vpnAddr)
	if rl != nil {
		cm = rl.CopyCache()
	}
	return json.NewEncoder(w.GetWriter()).Encode(cm)
}

func closeTunnelCommand(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	flags, ok := fs.(*closeTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *closeTunnelFlags but was %T", fs)
	}

	vpnAddr, err := parseVpnAddr(a, "vpn address", w)
	if err != nil {
		return err
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return commands.Fail(w, fmt.Sprintf("Could not find tunnel for vpn address: %v", a[0]))
	}

	if !flags.LocalOnly {
		ifce.sendCloseTunnel(hostInfo)
	}

	ifce.closeTunnel(hostInfo)
	return w.WriteLine("Closed")
}

func createTunnelCommand(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	flags, ok := fs.(*createTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *createTunnelFlags but was %T", fs)
	}

	vpnAddr, err := parseVpnAddr(a, "vpn address", w)
	if err != nil {
		return err
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo != nil {
		return commands.Fail(w, "Tunnel already exists")
	}

	hostInfo = ifce.handshakeManager.QueryVpnAddr(vpnAddr)
	if hostInfo != nil {
		return commands.Fail(w, "Tunnel already handshaking")
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

func changeRemoteCommand(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	flags, ok := fs.(*changeRemoteFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *changeRemoteFlags but was %T", fs)
	}

	vpnAddr, err := parseVpnAddr(a, "vpn address", w)
	if err != nil {
		return err
	}

	if flags.Address == "" {
		return commands.Fail(w, "No address was provided")
	}

	addr, err := netip.ParseAddrPort(flags.Address)
	if err != nil {
		return commands.Fail(w, "Address could not be parsed")
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return commands.Fail(w, fmt.Sprintf("Could not find tunnel for vpn address: %v", a[0]))
	}

	hostInfo.SetRemote(addr)
	return w.WriteLine("Changed")
}

func logLevelCommand(l *slog.Logger, fs any, a []string, w commands.StringWriter) error {
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

func logFormatCommand(l *slog.Logger, fs any, a []string, w commands.StringWriter) error {
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

func printCertCommand(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	args, ok := fs.(*printCertFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *printCertFlags but was %T", fs)
	}

	cert := ifce.pki.getCertState().GetDefaultCertificate()
	if len(a) > 0 {
		vpnAddr, err := parseVpnAddr(a, "vpn addr", w)
		if err != nil {
			return err
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

func printRelaysCommand(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	args, ok := fs.(*printTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *printTunnelFlags but was %T", fs)
	}

	ifce.hostMap.RLock()
	relays := maps.Clone(ifce.hostMap.Relays)
	ifce.hostMap.RUnlock()

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
	return enc.Encode(co)
}

func printTunnelCommand(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	args, ok := fs.(*printTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected *printTunnelFlags but was %T", fs)
	}

	vpnAddr, err := parseVpnAddr(a, "vpn addr", w)
	if err != nil {
		return err
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

func deviceInfoCommand(ifce *Interface, fs any, w commands.StringWriter) error {
	flags, ok := fs.(*deviceInfoFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be deviceInfoFlags but was %+v", fs)
	}

	data := struct {
		Name string         `json:"name"`
		Cidr []netip.Prefix `json:"cidr"`
	}{
		Name: ifce.inside.Name(),
		Cidr: make([]netip.Prefix, len(ifce.inside.Networks())),
	}

	copy(data.Cidr, ifce.inside.Networks())

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

// reloadCommand reloads the config and writes the result to the client. It reloads even if the client has gone away
func reloadCommand(l *slog.Logger, c *config.C, w commands.StringWriter) error {
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
