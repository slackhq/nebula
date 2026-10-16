package nebula

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/logging"
	"github.com/slackhq/nebula/sshd"
)

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

func wireSSHReload(l *slog.Logger, ssh *sshd.SSHServer, c *config.C) {
	c.RegisterReloadCallback(func(c *config.C, r *config.Reload) {
		if c.GetBool("sshd.enabled", false) {
			// Restarting the server drops every open session, the one that asked for this reload included. Only restart
			// when it isn't running or its config changed. The host key file can change under the same config, new
			// handshakes use the new key without a restart
			if ssh.Running() && !slices.ContainsFunc(sshdServerKeys, c.HasChanged) {
				key, err := loadSSHHostKey(c)
				if err == nil {
					err = ssh.SetHostKey(key)
				}
				if err != nil {
					l.Error("Failed to reconfigure the sshd", "error", err)
					ssh.Stop()
					r.Failed()
				}
				return
			}
			sshRun, err := configSSH(l, ssh, c, r)
			if err != nil {
				l.Error("Failed to reconfigure the sshd", "error", err)
				ssh.Stop()
				r.Failed()
			}
			if sshRun != nil {
				go sshRun()
			}
		} else {
			ssh.Stop()
		}
	})
}

// sshdServerKeys are what configSSH reads
var sshdServerKeys = []string{"sshd.enabled", "sshd.listen", "sshd.host_key", "sshd.trusted_cas", "sshd.authorized_users"}

// loadSSHHostKey returns sshd.host_key, read from its file when it names one.
func loadSSHHostKey(c *config.C) ([]byte, error) {
	hostKeyPathOrKey := c.GetString("sshd.host_key", "")
	if hostKeyPathOrKey == "" {
		return nil, fmt.Errorf("sshd.host_key must be provided")
	}
	if strings.Contains(hostKeyPathOrKey, "-----BEGIN") {
		return []byte(hostKeyPathOrKey), nil
	}
	b, err := os.ReadFile(hostKeyPathOrKey)
	if err != nil {
		return nil, fmt.Errorf("error while loading sshd.host_key file: %s", err)
	}
	return b, nil
}

// configSSH reads the ssh info out of the passed-in Config and
// updates the passed-in SSHServer. On success, it returns a function
// that callers may invoke to run the configured ssh server. On
// failure, it returns nil, error.
// r is nil at startup, entries that are skipped with a warning fail it on a reload
func configSSH(l *slog.Logger, ssh *sshd.SSHServer, c *config.C, r *config.Reload) (func(), error) {
	listen := c.GetString("sshd.listen", "")
	if listen == "" {
		return nil, fmt.Errorf("sshd.listen must be provided")
	}

	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, fmt.Errorf("invalid sshd.listen address: %s", err)
	}
	if port == "22" {
		return nil, fmt.Errorf("sshd.listen can not use port 22")
	}

	hostKeyBytes, err := loadSSHHostKey(c)
	if err != nil {
		return nil, err
	}

	err = ssh.SetHostKey(hostKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error while adding sshd.host_key: %s", err)
	}

	// Clear existing trusted CAs and authorized keys
	ssh.ClearTrustedCAs()
	ssh.ClearAuthorizedKeys()

	rawCAs := c.GetStringSlice("sshd.trusted_cas", []string{})
	for _, caAuthorizedKey := range rawCAs {
		err := ssh.AddTrustedCA(caAuthorizedKey)
		if err != nil {
			l.Warn("SSH CA had an error, ignoring", "error", err, "sshCA", caAuthorizedKey)
			r.Failed()
			continue
		}
	}

	rawKeys := c.Get("sshd.authorized_users")
	keys, ok := rawKeys.([]any)
	if ok {
		for _, rk := range keys {
			kDef, ok := rk.(map[string]any)
			if !ok {
				l.Warn("Authorized user had an error, ignoring", "sshKeyConfig", rk)
				r.Failed()
				continue
			}

			user, ok := kDef["user"].(string)
			if !ok {
				l.Warn("Authorized user is missing the user field", "sshKeyConfig", rk)
				r.Failed()
				continue
			}

			k := kDef["keys"]
			switch v := k.(type) {
			case string:
				err := ssh.AddAuthorizedKey(user, v)
				if err != nil {
					l.Warn("Failed to authorize key",
						"error", err,
						"sshKeyConfig", rk,
						"sshKey", v,
					)
					r.Failed()
					continue
				}

			case []any:
				for _, subK := range v {
					sk, ok := subK.(string)
					if !ok {
						l.Warn("Did not understand ssh key",
							"sshKeyConfig", rk,
							"sshKey", subK,
						)
						r.Failed()
						continue
					}

					err := ssh.AddAuthorizedKey(user, sk)
					if err != nil {
						l.Warn("Failed to authorize key",
							"error", err,
							"sshKeyConfig", sk,
						)
						r.Failed()
						continue
					}
				}

			default:
				l.Warn("Authorized user is missing the keys field or was not understood", "sshKeyConfig", rk)
				r.Failed()
			}
		}
	} else {
		l.Info("no ssh users to authorize")
	}

	var runner func()
	if c.GetBool("sshd.enabled", false) {
		ssh.Stop()
		runner = func() {
			if err := ssh.Run(listen); err != nil {
				l.Warn("Failed to run the SSH server", "error", err)
			}
		}
	} else {
		ssh.Stop()
	}

	return runner, nil
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
		return nil
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

		err := js.Encode(hm)
		if err != nil {
			return nil
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
		return nil
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

		err := js.Encode(addrMap)
		if err != nil {
			return nil
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
		return w.WriteLine("No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
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
		return nil
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn address: %v", a[0]))
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
		return nil
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo != nil {
		return w.WriteLine(fmt.Sprintf("Tunnel already exists"))
	}

	hostInfo = ifce.handshakeManager.QueryVpnAddr(vpnAddr)
	if hostInfo != nil {
		return w.WriteLine(fmt.Sprintf("Tunnel already handshaking"))
	}

	var addr netip.AddrPort
	if flags.Address != "" {
		addr, err = netip.ParseAddrPort(flags.Address)
		if err != nil {
			return w.WriteLine("Address could not be parsed")
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
		return nil
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn address was provided")
	}

	if flags.Address == "" {
		return w.WriteLine("No address was provided")
	}

	addr, err := netip.ParseAddrPort(flags.Address)
	if err != nil {
		return w.WriteLine("Address could not be parsed")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn address could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn address: %v", a[0]))
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
		return w.WriteLine("Log level is not reconfigurable on this logger")
	}

	if len(a) == 0 {
		return w.WriteLine(fmt.Sprintf("Log level is: %s", logging.LevelName(ctrl.GetLevel())))
	}

	level, err := logging.ParseLevel(strings.ToLower(a[0]))
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Unknown log level %s. Possible log levels: trace, debug, info, warn, error", a))
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
		return w.WriteLine("Log format is not reconfigurable on this logger")
	}

	if len(a) == 0 {
		return w.WriteLine(fmt.Sprintf("Log format is: %s", ctrl.GetFormat()))
	}

	if err := ctrl.SetFormat(strings.ToLower(a[0])); err != nil {
		return err
	}
	return w.WriteLine(fmt.Sprintf("Log format is: %s", ctrl.GetFormat()))
}

func sshPrintCert(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	args, ok := fs.(*sshPrintCertFlags)
	if !ok {
		return nil
	}

	cert := ifce.pki.getCertState().GetDefaultCertificate()
	if len(a) > 0 {
		vpnAddr, err := netip.ParseAddr(a[0])
		if err != nil {
			return w.WriteLine(fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
		}

		if !vpnAddr.IsValid() {
			return w.WriteLine(fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
		}

		hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
		if hostInfo == nil {
			return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn addr: %v", a[0]))
		}

		cert = hostInfo.GetCert().Certificate
	}

	if args.Json || args.Pretty {
		b, err := cert.MarshalJSON()
		if err != nil {
			return nil
		}

		if args.Pretty {
			buf := new(bytes.Buffer)
			err := json.Indent(buf, b, "", "    ")
			b = buf.Bytes()
			if err != nil {
				return nil
			}
		}

		return w.WriteBytes(b)
	}

	if args.Raw {
		b, err := cert.MarshalPEM()
		if err != nil {
			return nil
		}

		return w.WriteBytes(b)
	}

	return w.WriteLine(cert.String())
}

func sshPrintRelays(ifce *Interface, fs any, a []string, w commands.StringWriter) error {
	args, ok := fs.(*sshPrintTunnelFlags)
	if !ok {
		w.WriteLine(fmt.Sprintf("sshPrintRelays failed to convert args type"))
		return nil
	}

	relays := map[uint32]*HostInfo{}
	ifce.hostMap.Lock()
	maps.Copy(relays, ifce.hostMap.Relays)
	ifce.hostMap.Unlock()

	type RelayFor struct {
		Error          error
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
			ro.RelayForAddrs = append(ro.RelayForAddrs, RelayFor{Error: errors.New("could not find hostinfo")})
			continue
		}
		for _, vpnAddr := range relayHI.relayState.CopyRelayForIps() {
			rf := RelayFor{Error: nil}
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
					rf.Error = fmt.Errorf("hostmap LocalIndex '%v' does not match RelayState LocalIndex", k)
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
		return nil
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn address was provided")
	}

	vpnAddr, err := netip.ParseAddr(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
	}

	if !vpnAddr.IsValid() {
		return w.WriteLine(fmt.Sprintf("The provided vpn addr could not be parsed: %s", a[0]))
	}

	hostInfo := ifce.hostMap.QueryVpnAddr(vpnAddr)
	if hostInfo == nil {
		return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn addr: %v", a[0]))
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
	return writeErr
}
