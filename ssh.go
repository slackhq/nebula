package nebula

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
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

func wireSSHReload(l *logrus.Logger, ssh *sshd.SSHServer, c *config.C) {
	c.RegisterReloadCallback(func(c *config.C) {
		if c.GetBool("sshd.enabled", false) {
			sshRun, err := configSSH(l, ssh, c)
			if err != nil {
				l.WithError(err).Error("Failed to reconfigure the sshd")
				ssh.Stop()
			}
			if sshRun != nil {
				go sshRun()
			}
		} else {
			ssh.Stop()
		}
	})
}

// configSSH reads the ssh info out of the passed-in Config and
// updates the passed-in SSHServer. On success, it returns a function
// that callers may invoke to run the configured ssh server. On
// failure, it returns nil, error.
func configSSH(l *logrus.Logger, ssh *sshd.SSHServer, c *config.C) (func(), error) {
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

	hostKeyPathOrKey := c.GetString("sshd.host_key", "")
	if hostKeyPathOrKey == "" {
		return nil, fmt.Errorf("sshd.host_key must be provided")
	}

	var hostKeyBytes []byte
	if strings.Contains(hostKeyPathOrKey, "-----BEGIN") {
		hostKeyBytes = []byte(hostKeyPathOrKey)
	} else {
		hostKeyBytes, err = os.ReadFile(hostKeyPathOrKey)
		if err != nil {
			return nil, fmt.Errorf("error while loading sshd.host_key file: %s", err)
		}
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
			l.WithError(err).WithField("sshCA", caAuthorizedKey).Warn("SSH CA had an error, ignoring")
			continue
		}
	}

	rawKeys := c.Get("sshd.authorized_users")
	keys, ok := rawKeys.([]any)
	if ok {
		for _, rk := range keys {
			kDef, ok := rk.(map[string]any)
			if !ok {
				l.WithField("sshKeyConfig", rk).Warn("Authorized user had an error, ignoring")
				continue
			}

			user, ok := kDef["user"].(string)
			if !ok {
				l.WithField("sshKeyConfig", rk).Warn("Authorized user is missing the user field")
				continue
			}

			k := kDef["keys"]
			switch v := k.(type) {
			case string:
				err := ssh.AddAuthorizedKey(user, v)
				if err != nil {
					l.WithError(err).WithField("sshKeyConfig", rk).WithField("sshKey", v).Warn("Failed to authorize key")
					continue
				}

			case []any:
				for _, subK := range v {
					sk, ok := subK.(string)
					if !ok {
						l.WithField("sshKeyConfig", rk).WithField("sshKey", subK).Warn("Did not understand ssh key")
						continue
					}

					err := ssh.AddAuthorizedKey(user, sk)
					if err != nil {
						l.WithError(err).WithField("sshKeyConfig", sk).Warn("Failed to authorize key")
						continue
					}
				}

			default:
				l.WithField("sshKeyConfig", rk).Warn("Authorized user is missing the keys field or was not understood")
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
				l.WithField("err", err).Warn("Failed to run the SSH server")
			}
		}
	} else {
		ssh.Stop()
	}

	return runner, nil
}

func attachCommands(l *logrus.Logger, c *config.C, ssh *sshd.SSHServer, f *Interface) {
	ssh.RegisterCommand(&sshd.Command{
		Name:             "list-hostmap",
		ShortDescription: "List all known previously connected hosts",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshListHostMap(f.hostMap, fs, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "list-pending-hostmap",
		ShortDescription: "List all handshaking hosts",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.ByIndex, "by-index", false, "gets all hosts in the hostmap from the index table")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshListHostMap(f.handshakeManager, fs, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "list-lighthouse-addrmap",
		ShortDescription: "List all lighthouse map entries",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshListLighthouseMap(f.lightHouse, fs, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "reload",
		ShortDescription: "Reloads configuration from disk, same as sending HUP to the process",
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshReload(c, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "start-cpu-profile",
		ShortDescription: "Starts a cpu profile and write output to the provided file, ex: `cpu-profile.pb.gz`",
		Callback:         sshStartCpuProfile,
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "stop-cpu-profile",
		ShortDescription: "Stops a cpu profile and writes output to the previously provided file",
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			pprof.StopCPUProfile()
			return w.WriteLine("If a CPU profile was running it is now stopped")
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "save-heap-profile",
		ShortDescription: "Saves a heap profile to the provided path, ex: `heap-profile.pb.gz`",
		Callback:         sshGetHeapProfile,
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "mutex-profile-fraction",
		ShortDescription: "Gets or sets runtime.SetMutexProfileFraction",
		Callback:         sshMutexProfileFraction,
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "save-mutex-profile",
		ShortDescription: "Saves a mutex profile to the provided path, ex: `mutex-profile.pb.gz`",
		Callback:         sshGetMutexProfile,
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "log-level",
		ShortDescription: "Gets or sets the current log level",
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshLogLevel(l, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "log-format",
		ShortDescription: "Gets or sets the current log format",
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshLogFormat(l, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "version",
		ShortDescription: "Prints the currently running version of nebula",
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshVersion(f, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "device-info",
		ShortDescription: "Prints information about the network device.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshDeviceInfoFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshDeviceInfo(f, fs, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "print-cert",
		ShortDescription: "Prints the current certificate being used or the certificate for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintCertFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			fl.BoolVar(&s.Raw, "raw", false, "raw prints the PEM encoded certificate, not compatible with -json or -pretty")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshPrintCert(f, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "print-tunnel",
		ShortDescription: "Prints json details about a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshPrintTunnel(f, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "print-relays",
		ShortDescription: "Prints json details about all relay info",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshPrintRelays(f, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "change-remote",
		ShortDescription: "Changes the remote address used in the tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshChangeRemoteFlags{}
			fl.StringVar(&s.Address, "address", "", "The new remote address, ip:port")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshChangeRemote(f, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "close-tunnel",
		ShortDescription: "Closes a tunnel for the provided vpn addr",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshCloseTunnelFlags{}
			fl.BoolVar(&s.LocalOnly, "local-only", false, "Disables notifying the remote that the tunnel is shutting down")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshCloseTunnel(f, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "create-tunnel",
		ShortDescription: "Creates a tunnel for the provided vpn address",
		Help:             "The lighthouses will be queried for real addresses but you can provide one as well.",
		Flags: func() (*flag.FlagSet, any) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshCreateTunnelFlags{}
			fl.StringVar(&s.Address, "address", "", "Optionally provide a real remote address, ip:port ")
			return fl, &s
		},
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshCreateTunnel(f, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "query-lighthouse",
		ShortDescription: "Query the lighthouses for the provided vpn address",
		Help:             "This command is asynchronous. Only currently known udp addresses will be printed.",
		Callback: func(fs any, a []string, w sshd.StringWriter) error {
			return sshQueryLighthouse(f, fs, a, w)
		},
	})
}

func sshListHostMap(hl controlHostLister, a any, w sshd.StringWriter) error {
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

func sshListLighthouseMap(lightHouse *LightHouse, a any, w sshd.StringWriter) error {
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

func sshStartCpuProfile(fs any, a []string, w sshd.StringWriter) error {
	if len(a) == 0 {
		err := w.WriteLine("No path to write profile provided")
		return err
	}

	file, err := os.Create(a[0])
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

func sshVersion(ifce *Interface, fs any, a []string, w sshd.StringWriter) error {
	return w.WriteLine(fmt.Sprintf("%s", ifce.version))
}

func sshQueryLighthouse(ifce *Interface, fs any, a []string, w sshd.StringWriter) error {
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

func sshCloseTunnel(ifce *Interface, fs any, a []string, w sshd.StringWriter) error {
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

func sshCreateTunnel(ifce *Interface, fs any, a []string, w sshd.StringWriter) error {
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

	hostInfo = ifce.handshakeManager.StartHandshake(vpnAddr, nil)
	if addr.IsValid() {
		hostInfo.SetRemote(addr)
	}

	return w.WriteLine("Created")
}

func sshChangeRemote(ifce *Interface, fs any, a []string, w sshd.StringWriter) error {
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

func sshGetHeapProfile(fs any, a []string, w sshd.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine("No path to write profile provided")
	}

	file, err := os.Create(a[0])
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

func sshMutexProfileFraction(fs any, a []string, w sshd.StringWriter) error {
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

func sshGetMutexProfile(fs any, a []string, w sshd.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine("No path to write profile provided")
	}

	file, err := os.Create(a[0])
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

func sshLogLevel(l *logrus.Logger, fs any, a []string, w sshd.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine(fmt.Sprintf("Log level is: %s", l.Level))
	}

	level, err := logrus.ParseLevel(a[0])
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Unknown log level %s. Possible log levels: %s", a, logrus.AllLevels))
	}

	l.SetLevel(level)
	return w.WriteLine(fmt.Sprintf("Log level is: %s", l.Level))
}

func sshLogFormat(l *logrus.Logger, fs any, a []string, w sshd.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine(fmt.Sprintf("Log format is: %s", reflect.TypeOf(l.Formatter)))
	}

	logFormat := strings.ToLower(a[0])
	switch logFormat {
	case "text":
		l.Formatter = &logrus.TextFormatter{}
	case "json":
		l.Formatter = &logrus.JSONFormatter{}
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", logFormat, []string{"text", "json"})
	}

	return w.WriteLine(fmt.Sprintf("Log format is: %s", reflect.TypeOf(l.Formatter)))
}

func sshPrintCert(ifce *Interface, fs any, a []string, w sshd.StringWriter) error {
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

func sshPrintRelays(ifce *Interface, fs any, a []string, w sshd.StringWriter) error {
	args, ok := fs.(*sshPrintTunnelFlags)
	if !ok {
		w.WriteLine(fmt.Sprintf("sshPrintRelays failed to convert args type"))
		return nil
	}

	relays := map[uint32]*HostInfo{}
	ifce.hostMap.Lock()
	for k, v := range ifce.hostMap.Relays {
		relays[k] = v
	}
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

func sshPrintTunnel(ifce *Interface, fs any, a []string, w sshd.StringWriter) error {
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

func sshDeviceInfo(ifce *Interface, fs any, w sshd.StringWriter) error {

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

func sshReload(c *config.C, w sshd.StringWriter) error {
	err := w.WriteLine("Reloading config")
	c.ReloadConfig()
	return err
}
