package nebula

// The commands nebula exposes for debugging and administration. They are transport neutral:
// the ssh console in ssh.go and the `nebula ctl` socket in ctl.go both dispatch against the
// registry attachCommands fills in, and a command cannot tell which one invoked it. Adding a
// command here makes it available over both.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/diag"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/logging"
)

type listHostMapFlags struct {
	Json    bool
	Pretty  bool
	ByIndex bool
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

func attachCommands(l *slog.Logger, c *config.C, reg *diag.Registry, f *Interface) {
	// sandboxDir defaults to a dir in temp. The intention is that end user will
	// create this dir as needed. Overriding this config value to "" allows
	// writing to anywhere in the system.
	defaultDir := filepath.Join(os.TempDir(), "nebula-debug")
	// The key is spelled for both transports now: the profile writers are reachable over
	// `nebula ctl` as well, but sshd.sandbox_dir keeps working for anyone already setting it.
	sandboxDir := c.GetString("ctl.sandbox_dir", c.GetString("sshd.sandbox_dir", defaultDir))

	reg.RegisterCommand(&diag.Command{
		Name:             "list-hostmap",
		ShortDescription: "List all known previously connected hosts",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := listHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdListHostMap(f.hostMap, fs, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "list-pending-hostmap",
		ShortDescription: "List all handshaking hosts",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := listHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdListHostMap(f.handshakeManager, fs, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "list-lighthouse-addrmap",
		ShortDescription: "List all lighthouse map entries",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := listHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdListLighthouseMap(f.lightHouse, fs, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "reload",
		ShortDescription: "Reloads configuration from disk, same as sending HUP to the process",
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdReload(c, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "start-cpu-profile",
		ShortDescription: "Starts a cpu profile and write output to the provided file, ex: `cpu-profile.pb.gz`",
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdStartCpuProfile(sandboxDir, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "stop-cpu-profile",
		ShortDescription: "Stops a cpu profile and writes output to the previously provided file",
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			pprof.StopCPUProfile()
			return w.WriteLine("If a CPU profile was running it is now stopped")
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "save-heap-profile",
		ShortDescription: "Saves a heap profile to the provided path, ex: `heap-profile.pb.gz`",
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdGetHeapProfile(sandboxDir, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "mutex-profile-fraction",
		ShortDescription: "Gets or sets runtime.SetMutexProfileFraction",
		Callback:         cmdMutexProfileFraction,
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "save-mutex-profile",
		ShortDescription: "Saves a mutex profile to the provided path, ex: `mutex-profile.pb.gz`",
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdGetMutexProfile(sandboxDir, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "log-level",
		ShortDescription: "Gets or sets the current log level",
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdLogLevel(l, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "log-format",
		ShortDescription: "Gets or sets the current log format",
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdLogFormat(l, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "version",
		ShortDescription: "Prints the currently running version of nebula",
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdVersion(f, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "device-info",
		ShortDescription: "Prints information about the network device.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := deviceInfoFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdDeviceInfo(f, fs, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "print-cert",
		ShortDescription: "Prints the current certificate being used or the certificate for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := printCertFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.Raw, "raw", false, "raw prints the PEM encoded certificate, not compatible with -json or -pretty")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdPrintCert(f, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "print-tunnel",
		ShortDescription: "Prints json details about a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := printTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdPrintTunnel(f, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "print-relays",
		ShortDescription: "Prints json details about all relay info",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := printTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdPrintRelays(f, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "change-remote",
		ShortDescription: "Changes the remote address used in the tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := changeRemoteFlags{}
			fl.StringVar(&s.Address, "address", "", "The new remote address, ip:port")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdChangeRemote(f, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "close-tunnel",
		ShortDescription: "Closes a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := closeTunnelFlags{}
			fl.BoolVar(&s.LocalOnly, "local-only", false, "Disables notifying the remote that the tunnel is shutting down")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdCloseTunnel(f, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "create-tunnel",
		ShortDescription: "Creates a tunnel for the provided vpn address",
		Help:             "The lighthouses will be queried for real addresses but you can provide one as well.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := createTunnelFlags{}
			fl.StringVar(&s.Address, "address", "", "Optionally provide a real remote address, ip:port ")
			return fl, &s
		},
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdCreateTunnel(f, fs, a, w)
		},
	})

	reg.RegisterCommand(&diag.Command{
		Name:             "query-lighthouse",
		ShortDescription: "Query the lighthouses for the provided vpn address",
		Help:             "This command is asynchronous. Only currently known udp addresses will be printed.",
		Callback: func(fs any, a []string, w diag.StringWriter) error {
			return cmdQueryLighthouse(f, fs, a, w)
		},
	})
}

func cmdListHostMap(hl controlHostLister, a any, w diag.StringWriter) error {
	fs, ok := a.(*listHostMapFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be listHostMapFlags but was %+v", a)
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

func cmdListLighthouseMap(lightHouse *LightHouse, a any, w diag.StringWriter) error {
	fs, ok := a.(*listHostMapFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be listHostMapFlags but was %+v", a)
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

// sanitizeFilePath validates that the given file path is within the sandbox directory.
// If sandboxDir is empty, the path is returned as-is for backwards compatibility.
func sanitizeFilePath(sandboxDir, filePath string) (string, error) {
	if sandboxDir == "" {
		return filePath, nil
	}

	// Clean and resolve the path relative to the sandbox directory
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(sandboxDir, filePath)
	}
	cleaned := filepath.Clean(filePath)

	// Ensure the resolved path is within the sandbox directory
	cleanedSandbox := filepath.Clean(sandboxDir)
	if cleaned == cleanedSandbox {
		return "", fmt.Errorf("path %q resolves to the sandbox directory itself %q", filePath, sandboxDir)
	}
	if !strings.HasPrefix(cleaned, cleanedSandbox+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside the sandbox directory %q", filePath, sandboxDir)
	}

	return cleaned, nil
}

func cmdStartCpuProfile(sandboxDir string, fs any, a []string, w diag.StringWriter) error {
	if len(a) == 0 {
		err := w.WriteLine("No path to write profile provided")
		return err
	}

	filePath, err := sanitizeFilePath(sandboxDir, a[0])
	if err != nil {
		return w.WriteLine(err.Error())
	}

	file, err := os.Create(filePath)
	if err != nil {
		err = w.WriteLine(fmt.Sprintf("Unable to create profile file: %s", err))
		return err
	}

	err = pprof.StartCPUProfile(file)
	if err != nil {
		err = w.WriteLine(fmt.Sprintf("Unable to start cpu profile: %s", err))
		return err
	}

	err = w.WriteLine(fmt.Sprintf("Started cpu profile, issue stop-cpu-profile to write the output to %s", a))
	return err
}

func cmdVersion(ifce *Interface, fs any, a []string, w diag.StringWriter) error {
	return w.WriteLine(fmt.Sprintf("%s", ifce.version))
}

func cmdQueryLighthouse(ifce *Interface, fs any, a []string, w diag.StringWriter) error {
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

func cmdCloseTunnel(ifce *Interface, fs any, a []string, w diag.StringWriter) error {
	flags, ok := fs.(*closeTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be closeTunnelFlags but was %+v", fs)
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

func cmdCreateTunnel(ifce *Interface, fs any, a []string, w diag.StringWriter) error {
	flags, ok := fs.(*createTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be createTunnelFlags but was %+v", fs)
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

	hostInfo = ifce.handshakeManager.StartHandshake(vpnAddr, nil)
	if addr.IsValid() {
		hostInfo.SetRemote(addr)
	}

	return w.WriteLine("Created")
}

func cmdChangeRemote(ifce *Interface, fs any, a []string, w diag.StringWriter) error {
	flags, ok := fs.(*changeRemoteFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be changeRemoteFlags but was %+v", fs)
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

func cmdGetHeapProfile(sandboxDir string, fs any, a []string, w diag.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine("No path to write profile provided")
	}

	filePath, err := sanitizeFilePath(sandboxDir, a[0])
	if err != nil {
		return w.WriteLine(err.Error())
	}

	file, err := os.Create(filePath)
	if err != nil {
		err = w.WriteLine(fmt.Sprintf("Unable to create profile file: %s", err))
		return err
	}

	err = pprof.WriteHeapProfile(file)
	if err != nil {
		err = w.WriteLine(fmt.Sprintf("Unable to write profile: %s", err))
		return err
	}

	err = w.WriteLine(fmt.Sprintf("Mem profile created at %s", a))
	return err
}

func cmdMutexProfileFraction(fs any, a []string, w diag.StringWriter) error {
	if len(a) == 0 {
		rate := runtime.SetMutexProfileFraction(-1)
		return w.WriteLine(fmt.Sprintf("Current value: %d", rate))
	}

	newRate, err := strconv.Atoi(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Invalid argument: %s", a[0]))
	}

	oldRate := runtime.SetMutexProfileFraction(newRate)
	return w.WriteLine(fmt.Sprintf("New value: %d. Old value: %d", newRate, oldRate))
}

func cmdGetMutexProfile(sandboxDir string, fs any, a []string, w diag.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine("No path to write profile provided")
	}

	filePath, err := sanitizeFilePath(sandboxDir, a[0])
	if err != nil {
		return w.WriteLine(err.Error())
	}

	file, err := os.Create(filePath)
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Unable to create profile file: %s", err))
	}
	defer file.Close()

	mutexProfile := pprof.Lookup("mutex")
	if mutexProfile == nil {
		return w.WriteLine("Unable to get pprof.Lookup(\"mutex\")")
	}

	err = mutexProfile.WriteTo(file, 0)
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Unable to write profile: %s", err))
	}

	return w.WriteLine(fmt.Sprintf("Mutex profile created at %s", a))
}

func cmdLogLevel(l *slog.Logger, fs any, a []string, w diag.StringWriter) error {
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

func cmdLogFormat(l *slog.Logger, fs any, a []string, w diag.StringWriter) error {
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

func cmdPrintCert(ifce *Interface, fs any, a []string, w diag.StringWriter) error {
	args, ok := fs.(*printCertFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be printCertFlags but was %+v", fs)
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

func cmdPrintRelays(ifce *Interface, fs any, a []string, w diag.StringWriter) error {
	args, ok := fs.(*printTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be printTunnelFlags but was %+v", fs)
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

func cmdPrintTunnel(ifce *Interface, fs any, a []string, w diag.StringWriter) error {
	args, ok := fs.(*printTunnelFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be printTunnelFlags but was %+v", fs)
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

func cmdDeviceInfo(ifce *Interface, fs any, w diag.StringWriter) error {

	data := struct {
		Name string         `json:"name"`
		Cidr []netip.Prefix `json:"cidr"`
	}{
		Name: ifce.inside.Name(),
		Cidr: make([]netip.Prefix, len(ifce.inside.Networks())),
	}

	copy(data.Cidr, ifce.inside.Networks())

	flags, ok := fs.(*deviceInfoFlags)
	if !ok {
		return fmt.Errorf("internal error: expected flags to be deviceInfoFlags but was %+v", fs)
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

func cmdReload(c *config.C, w diag.StringWriter) error {
	err := w.WriteLine("Reloading config")
	c.ReloadConfig()
	return err
}
