package nebula

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"sort"
	"strings"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/logging"
)

// The commands nebula serves. attachCommands builds the one registry every surface
// reads; the ssh debug server is a consumer of it, not its owner, which is why this
// is not ssh.go. See the commands package for what a Command is.

type listHostMapFlags struct {
	ByIndex bool
}

type printCertFlags struct {
	Raw bool
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

// lighthouseInfo is one entry of list-lighthouse-addrmap.
type lighthouseInfo struct {
	VpnAddr string    `json:"vpnAddr"`
	Addrs   *CacheMap `json:"addrs"`
}

// deviceInfo is the result of device-info.
type deviceInfo struct {
	Name string         `json:"name"`
	Cidr []netip.Prefix `json:"cidr"`
}

// certPEM is the result of print-cert -raw. The PEM form is a different thing to emit,
// not a different formatting of the certificate, so it is its own shape.
type certPEM struct {
	PEM string `json:"pem"`
}

// Result shapes for print-relays. Field names are the JSON keys; changing them would
// change the output.
type relayFor struct {
	Error          string `json:",omitempty"`
	Type           string
	State          string
	PeerAddr       netip.Addr
	LocalIndex     uint32
	RemoteIndex    uint32
	RelayedThrough []netip.Addr
}

type relayOutput struct {
	NebulaAddr    netip.Addr
	RelayForAddrs []relayFor
}

type relaysOutput struct {
	Relays []*relayOutput
}

type versionInfo struct {
	Version string `json:"version"`
}

type logLevelInfo struct {
	Level string `json:"level"`
}

type logFormatInfo struct {
	Format string `json:"format"`
}

// defineListHostMapFlags declares the flags list-hostmap and list-pending-hostmap share.
func defineListHostMapFlags(fl *flag.FlagSet, s *listHostMapFlags) {
	fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
}

func attachCommands(l *slog.Logger, c *config.C, reg *commands.Registry, f *Interface) {
	reg.Register(commands.Flagged(&commands.Command{
		Name:             commands.ListHostmap,
		ShortDescription: "List all known previously connected hosts",
		Text:             commands.Typed(textListHostMap),
	}, defineListHostMapFlags, func(s *listHostMapFlags, a []string) (commands.Result, error) {
		return runListHostMap(f.hostMap, s)
	}))

	reg.Register(commands.Flagged(&commands.Command{
		Name:             commands.ListPendingHostmap,
		ShortDescription: "List all handshaking hosts",
		Text:             commands.Typed(textListHostMap),
	}, defineListHostMapFlags, func(s *listHostMapFlags, a []string) (commands.Result, error) {
		return runListHostMap(f.handshakeManager, s)
	}))

	reg.Register(&commands.Command{
		Name:             commands.ListLighthouseAddrmap,
		ShortDescription: "List all lighthouse map entries",
		Run: func(fs any, a []string) (commands.Result, error) {
			return runListLighthouseMap(f.lightHouse)
		},
		Text: commands.Typed(textListLighthouseMap),
	})

	reg.Register(&commands.Command{
		Name:             commands.Reload,
		ShortDescription: "Reloads configuration from disk, same as sending HUP to the process",
		// The line goes out before the reload: a reload that restarts the ssh server ends
		// the session that asked, and this is what it sees.
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Did("Reloading config"), nil
		},
		Then: func() commands.Result {
			return runReload(l, c)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.LogLevel,
		ShortDescription: "Gets or sets the current log level",
		Run: func(fs any, a []string) (commands.Result, error) {
			return runLogLevel(l, a)
		},
		Text: commands.Typed(textLogLevel),
	})

	reg.Register(&commands.Command{
		Name:             commands.LogFormat,
		ShortDescription: "Gets or sets the current log format",
		Run: func(fs any, a []string) (commands.Result, error) {
			return runLogFormat(l, a)
		},
		Text: commands.Typed(textLogFormat),
	})

	reg.Register(&commands.Command{
		Name:             commands.Version,
		ShortDescription: "Prints the currently running version of nebula",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Value(versionInfo{Version: f.version}), nil
		},
		Text: commands.Typed(textVersion),
	})

	reg.Register(&commands.Command{
		Name:             commands.DeviceInfo,
		ShortDescription: "Prints information about the network device.",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Value(runDeviceInfo(f)), nil
		},
		Text: commands.Typed(textDeviceInfo),
	})

	reg.Register(commands.Flagged(&commands.Command{
		Name:             commands.PrintCert,
		ShortDescription: "Prints the current certificate being used or the certificate for the provided vpn addr",
		Text:             textPrintCert,
	}, func(fl *flag.FlagSet, s *printCertFlags) {
		fl.BoolVar(&s.Raw, "raw", false, "prints the PEM encoded certificate; with -json, an object holding it")
	}, func(s *printCertFlags, a []string) (commands.Result, error) {
		return runPrintCert(f, s, a)
	}))

	reg.Register(commands.Flagged(&commands.Command{
		Name:             commands.Identity,
		ShortDescription: "Prints the certificate identity of the host owning the provided vpn addr",
		Help:             "The printed identity includes: name, vpn addrs, networks, groups, fingerprint, issuer and validity. The query address may include a port. For this node's own identity use whoami.",
		Identity:         true,
		Text:             commands.Typed(textIdentity),
	}, func(fl *flag.FlagSet, s *identityFlags) {
		fl.Func("address", "The vpn addr to look up, optionally with a port", s.setAddress)
	}, func(s *identityFlags, a []string) (commands.Result, error) {
		return runIdentity(f, s, a)
	}))

	reg.Register(&commands.Command{
		Name:             commands.Whoami,
		ShortDescription: "Prints the certificate identity of this node",
		Help:             "Prints the name, vpn addrs, networks, groups, fingerprint, issuer and validity for this node's certificate.",
		Identity:         true,
		Text:             commands.Typed(textIdentity),
		Run: func(fs any, a []string) (commands.Result, error) {
			if len(a) > 0 {
				return commands.Failed("whoami takes no arguments"), nil
			}
			return runWhoami(f)
		},
	})

	reg.Register(&commands.Command{
		Name:             commands.PrintTunnel,
		ShortDescription: "Prints json details about a tunnel for the provided vpn addr",
		Run: func(fs any, a []string) (commands.Result, error) {
			return runPrintTunnel(f, a)
		},
		// No Text on purpose: nothing human readable exists yet, and shipping an interim
		// form would invite scripts against it. ssh defaults these to JSON; ctl asks.
		JSONOnly: true,
	})

	reg.Register(&commands.Command{
		Name:             commands.PrintRelays,
		ShortDescription: "Prints json details about all relay info",
		Run: func(fs any, a []string) (commands.Result, error) {
			return commands.Value(runPrintRelays(f)), nil
		},
		// No Text on purpose; see print-tunnel.
		JSONOnly: true,
	})

	reg.Register(commands.Flagged(&commands.Command{
		Name:             commands.ChangeRemote,
		ShortDescription: "Changes the remote address used in the tunnel for the provided vpn addr",
	}, func(fl *flag.FlagSet, s *changeRemoteFlags) {
		fl.StringVar(&s.Address, "address", "", "The new remote address, ip:port")
	}, func(s *changeRemoteFlags, a []string) (commands.Result, error) {
		return runChangeRemote(f, s, a)
	}))

	reg.Register(commands.Flagged(&commands.Command{
		Name:             commands.CloseTunnel,
		ShortDescription: "Closes a tunnel for the provided vpn addr",
	}, func(fl *flag.FlagSet, s *closeTunnelFlags) {
		fl.BoolVar(&s.LocalOnly, "local-only", false, "Disables notifying the remote that the tunnel is shutting down")
	}, func(s *closeTunnelFlags, a []string) (commands.Result, error) {
		return runCloseTunnel(f, s, a)
	}))

	reg.Register(commands.Flagged(&commands.Command{
		Name:             commands.CreateTunnel,
		ShortDescription: "Creates a tunnel for the provided vpn address",
		Help:             "The lighthouses will be queried for real addresses but you can provide one as well.",
	}, func(fl *flag.FlagSet, s *createTunnelFlags) {
		fl.StringVar(&s.Address, "address", "", "Optionally provide a real remote address, ip:port ")
	}, func(s *createTunnelFlags, a []string) (commands.Result, error) {
		return runCreateTunnel(f, s, a)
	}))

	reg.Register(&commands.Command{
		Name:             commands.QueryLighthouse,
		ShortDescription: "Query the lighthouses for the provided vpn address",
		Help:             "This command is asynchronous. Only currently known udp addresses will be printed.",
		Run: func(fs any, a []string) (commands.Result, error) {
			return runQueryLighthouse(f, a)
		},
		// No Text on purpose; see print-tunnel.
		JSONOnly: true,
	})
}

// runListHostMap computes the hostmap listing. Presentation is Render's job.
func runListHostMap(hl controlHostLister, fs *listHostMapFlags) (commands.Result, error) {
	var hm []ControlHostInfo
	if fs.ByIndex {
		hm = listHostMapIndexes(hl)
	} else {
		hm = listHostMapHosts(hl)
	}

	sort.Slice(hm, func(i, j int) bool {
		return hm[i].VpnAddrs[0].Compare(hm[j].VpnAddrs[0]) < 0
	})

	return commands.Value(hm), nil
}

// textListHostMap is the human rendering, shared by every surface.
func textListHostMap(hm []ControlHostInfo, w io.Writer) error {
	for _, h := range hm {
		if _, err := fmt.Fprintf(w, "%s: %s\n", h.VpnAddrs, h.RemoteAddrs); err != nil {
			return err
		}
	}

	return nil
}

func runListLighthouseMap(lightHouse *LightHouse) (commands.Result, error) {
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

	return commands.Value(addrMap), nil
}

func textListLighthouseMap(addrMap []lighthouseInfo, w io.Writer) error {
	for _, e := range addrMap {
		b, err := json.Marshal(e.Addrs)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s: %s\n", e.VpnAddr, string(b)); err != nil {
			return err
		}
	}

	return nil
}

func textVersion(vi versionInfo, w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s\n", vi.Version)
	return err
}

// vpnAddrOperand parses the vpn address a command takes as its first operand. noun is
// how the command's messages name it, "vpn address" or "vpn addr", which the output
// golden pins per command. With no operand, or one that does not parse, ok is false and
// res is the refusal to return.
func vpnAddrOperand(a []string, noun string) (vpnAddr netip.Addr, res commands.Result, ok bool) {
	if len(a) == 0 {
		return netip.Addr{}, commands.Failed("No vpn address was provided"), false
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return netip.Addr{}, commands.Failed("The provided %s could not be parsed: %s", noun, a[0]), false
	}

	return vpnAddr, commands.Result{}, true
}

// tunnelOperand is vpnAddrOperand followed by the lookup of the tunnel it names.
func tunnelOperand(ifce *Interface, a []string, noun string) (*HostInfo, commands.Result, bool) {
	vpnAddr, res, ok := vpnAddrOperand(a, noun)
	if !ok {
		return nil, res, false
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return nil, commands.Failed("Could not find tunnel for %s: %v", noun, a[0]), false
	}

	return hostInfo, commands.Result{}, true
}

func runQueryLighthouse(ifce *Interface, a []string) (commands.Result, error) {
	vpnAddr, res, ok := vpnAddrOperand(a, "vpn address")
	if !ok {
		return res, nil
	}

	var cm *CacheMap
	rl := ifce.lightHouse.Query(vpnAddr)
	if rl != nil {
		cm = rl.CopyCache()
	}
	return commands.Value(cm), nil
}

func runCloseTunnel(ifce *Interface, flags *closeTunnelFlags, a []string) (commands.Result, error) {
	hostInfo, res, ok := tunnelOperand(ifce, a, "vpn address")
	if !ok {
		return res, nil
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
	return commands.Did("Closed"), nil
}

func runCreateTunnel(ifce *Interface, flags *createTunnelFlags, a []string) (commands.Result, error) {

	vpnAddr, res, ok := vpnAddrOperand(a, "vpn address")
	if !ok {
		return res, nil
	}

	if hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr); hostInfo != nil {
		return commands.Failed("Tunnel already exists"), nil
	}

	if hostInfo := ifce.handshakeManager.QueryVpnAddr(vpnAddr); hostInfo != nil {
		return commands.Failed("Tunnel already handshaking"), nil
	}

	var addr netip.AddrPort
	if flags.Address != "" {
		var err error
		addr, err = netip.ParseAddrPort(flags.Address)
		if err != nil {
			return commands.Failed("Address could not be parsed"), nil
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

	return commands.Did("Created"), nil
}

func runChangeRemote(ifce *Interface, flags *changeRemoteFlags, a []string) (commands.Result, error) {

	if len(a) == 0 {
		return commands.Failed("No vpn address was provided"), nil
	}

	if flags.Address == "" {
		return commands.Failed("No address was provided"), nil
	}

	addr, err := netip.ParseAddrPort(flags.Address)
	if err != nil {
		return commands.Failed("Address could not be parsed"), nil
	}

	hostInfo, res, ok := tunnelOperand(ifce, a, "vpn address")
	if !ok {
		return res, nil
	}

	hostInfo.SetRemote(addr)
	return commands.Did("Changed"), nil
}

func runLogLevel(l *slog.Logger, a []string) (commands.Result, error) {
	ctrl, ok := l.Handler().(interface {
		GetLevel() slog.Level
		SetLevel(slog.Level)
	})
	if !ok {
		return commands.Failed("Log level is not reconfigurable on this logger"), nil
	}

	if len(a) > 0 {
		level, err := logging.ParseLevel(strings.ToLower(a[0]))
		if err != nil {
			return commands.Failed("Unknown log level %s. Possible log levels: trace, debug, info, warn, error", a), nil
		}

		ctrl.SetLevel(level)
	}

	return commands.Value(logLevelInfo{Level: logging.LevelName(ctrl.GetLevel())}), nil
}

func textLogLevel(li logLevelInfo, w io.Writer) error {
	_, err := fmt.Fprintf(w, "Log level is: %s\n", li.Level)
	return err
}

func runLogFormat(l *slog.Logger, a []string) (commands.Result, error) {
	ctrl, ok := l.Handler().(interface {
		GetFormat() string
		SetFormat(string) error
	})
	if !ok {
		return commands.Failed("Log format is not reconfigurable on this logger"), nil
	}

	if len(a) > 0 {
		if err := ctrl.SetFormat(strings.ToLower(a[0])); err != nil {
			return commands.Failed("Unable to set log format: %s", err), nil
		}
	}

	return commands.Value(logFormatInfo{Format: ctrl.GetFormat()}), nil
}

func textLogFormat(fi logFormatInfo, w io.Writer) error {
	_, err := fmt.Fprintf(w, "Log format is: %s\n", fi.Format)
	return err
}

func runPrintCert(ifce *Interface, args *printCertFlags, a []string) (commands.Result, error) {

	c := ifce.pki.getCertState().GetDefaultCertificate()
	if len(a) > 0 {
		hostInfo, res, ok := tunnelOperand(ifce, a, "vpn addr")
		if !ok {
			return res, nil
		}
		// A tunnel still handshaking, or one being torn down, has no certificate.
		cc := hostInfo.GetCert()
		if cc == nil {
			return commands.Failed("Could not find tunnel for vpn addr: %v", a[0]), nil
		}
		c = cc.Certificate
	}

	if args.Raw {
		b, err := c.MarshalPEM()
		if err != nil {
			return commands.Failed("Unable to marshal the certificate: %s", err), nil
		}
		return commands.Value(certPEM{PEM: string(b)}), nil
	}

	return commands.Value(c), nil
}

// textPrintCert takes the value untyped: print-cert returns a certificate or, with -raw,
// its PEM, and those are two things to emit rather than two renderings of one.
func textPrintCert(v any, w io.Writer) error {
	switch c := v.(type) {
	case certPEM:
		_, err := io.WriteString(w, c.PEM)
		return err
	case cert.Certificate:
		_, err := io.WriteString(w, c.String()+"\n")
		return err
	default:
		return fmt.Errorf("expected a certificate, got %T", v)
	}
}

func runPrintRelays(ifce *Interface) any {
	ifce.hostMap.RLock()
	relays := maps.Clone(ifce.hostMap.Relays)
	ifce.hostMap.RUnlock()

	co := relaysOutput{}

	for k, v := range relays {
		ro := relayOutput{NebulaAddr: v.vpnAddrs[0]}
		co.Relays = append(co.Relays, &ro)
		relayHI := ifce.hostMap.QueryVpnAddr(v.vpnAddrs[0])
		if relayHI == nil {
			ro.RelayForAddrs = append(ro.RelayForAddrs, relayFor{Error: "could not find hostinfo"})
			continue
		}
		for _, vpnAddr := range relayHI.relayState.CopyRelayForIps() {
			rf := relayFor{}
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

				st := ""
				switch r.State {
				case Requested:
					st = "requested"
				case Established:
					st = "established"
				default:
					st = "unknown"
				}

				rf.LocalIndex = r.LocalIndex
				rf.RemoteIndex = r.RemoteIndex
				rf.PeerAddr = r.PeerAddr
				rf.Type = t
				rf.State = st
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

	return co
}

func runPrintTunnel(ifce *Interface, a []string) (commands.Result, error) {
	hostInfo, res, ok := tunnelOperand(ifce, a, "vpn addr")
	if !ok {
		return res, nil
	}

	return commands.Value(copyHostInfo(hostInfo, ifce.hostMap.GetPreferredRanges())), nil
}

func runDeviceInfo(ifce *Interface) deviceInfo {
	d := deviceInfo{
		Name: ifce.inside.Name(),
		Cidr: make([]netip.Prefix, len(ifce.inside.Networks())),
	}
	copy(d.Cidr, ifce.inside.Networks())
	return d
}

func textDeviceInfo(d deviceInfo, w io.Writer) error {
	_, err := fmt.Fprintf(w, "name=%v cidr=%v\n", d.Name, d.Cidr)
	return err
}

// runReload reloads the config and reports how it went. A reload that failed is a
// refusal, exit 1 over ssh; one that merely needs a restart is not.
func runReload(l *slog.Logger, c *config.C) commands.Result {
	res := c.ReloadConfig()
	res.Log(l)
	if res.Err != nil || res.Failed {
		return commands.Failed("%s", res.String())
	}
	return commands.Did("%s", res.String())
}
