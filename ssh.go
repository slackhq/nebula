package nebula

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"runtime/pprof"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/sshd"
)

type sshListHostMapFlags struct {
	Json   bool
	Pretty bool
}

type sshPrintCertFlags struct {
	Json   bool
	Pretty bool
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

func wireSSHReload(ssh *sshd.SSHServer, c *Config) {
	c.RegisterReloadCallback(func(c *Config) {
		if c.GetBool("sshd.enabled", false) {
			err := configSSH(ssh, c)
			if err != nil {
				l.WithError(err).Error("Failed to reconfigure the sshd")
				ssh.Stop()
			}
		} else {
			ssh.Stop()
		}
	})
}

func configSSH(ssh *sshd.SSHServer, c *Config) error {
	//TODO conntrack list
	//TODO print firewall rules or hash?

	listen := c.GetString("sshd.listen", "")
	if listen == "" {
		return fmt.Errorf("sshd.listen must be provided")
	}

	port := strings.Split(listen, ":")
	if len(port) < 2 {
		return fmt.Errorf("sshd.listen does not have a port")
	} else if port[1] == "22" {
		return fmt.Errorf("sshd.listen can not use port 22")
	}

	//TODO: no good way to reload this right now
	hostKeyFile := c.GetString("sshd.host_key", "")
	if hostKeyFile == "" {
		return fmt.Errorf("sshd.host_key must be provided")
	}

	hostKeyBytes, err := ioutil.ReadFile(hostKeyFile)
	if err != nil {
		return fmt.Errorf("error while loading sshd.host_key file: %s", err)
	}

	err = ssh.SetHostKey(hostKeyBytes)
	if err != nil {
		return fmt.Errorf("error while adding sshd.host_key: %s", err)
	}

	rawKeys := c.Get("sshd.authorized_users")
	keys, ok := rawKeys.([]interface{})
	if ok {
		for _, rk := range keys {
			kDef, ok := rk.(map[interface{}]interface{})
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

			case []interface{}:
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

	if c.GetBool("sshd.enabled", false) {
		ssh.Stop()
		go ssh.Run(listen)
	} else {
		ssh.Stop()
	}

	return nil
}

func attachCommands(ssh *sshd.SSHServer, hostMap *HostMap, pendingHostMap *HostMap, lightHouse *LightHouse, ifce *Interface) {
	ssh.RegisterCommand(&sshd.Command{
		Name:             "list-hostmap",
		ShortDescription: "List all known previously connected hosts",
		Flags: func() (*flag.FlagSet, interface{}) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshListHostMap(hostMap, fs, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "list-pending-hostmap",
		ShortDescription: "List all handshaking hosts",
		Flags: func() (*flag.FlagSet, interface{}) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshListHostMap(pendingHostMap, fs, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "list-lighthouse-addrmap",
		ShortDescription: "List all lighthouse map entries",
		Flags: func() (*flag.FlagSet, interface{}) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshListHostMapFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json with more information")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshListLighthouseMap(lightHouse, fs, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "reload",
		ShortDescription: "Reloads configuration from disk, same as sending HUP to the process",
		Callback:         sshReload,
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "start-cpu-profile",
		ShortDescription: "Starts a cpu profile and write output to the provided file",
		Callback:         sshStartCpuProfile,
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "stop-cpu-profile",
		ShortDescription: "Stops a cpu profile and writes output to the previously provided file",
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			pprof.StopCPUProfile()
			return w.WriteLine("If a CPU profile was running it is now stopped")
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "save-heap-profile",
		ShortDescription: "Saves a heap profile to the provided path",
		Callback:         sshGetHeapProfile,
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "log-level",
		ShortDescription: "Gets or sets the current log level",
		Callback:         sshLogLevel,
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "log-format",
		ShortDescription: "Gets or sets the current log format",
		Callback:         sshLogFormat,
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "version",
		ShortDescription: "Prints the currently running version of nebula",
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshVersion(ifce, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "print-cert",
		ShortDescription: "Prints the current certificate being used or the certificate for the provided vpn ip",
		Flags: func() (*flag.FlagSet, interface{}) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintCertFlags{}
			fl.BoolVar(&s.Json, "json", false, "outputs as json")
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json, assumes -json")
			return fl, &s
		},
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshPrintCert(ifce, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "print-tunnel",
		ShortDescription: "Prints json details about a tunnel for the provided vpn ip",
		Flags: func() (*flag.FlagSet, interface{}) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshPrintTunnelFlags{}
			fl.BoolVar(&s.Pretty, "pretty", false, "pretty prints json")
			return fl, &s
		},
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshPrintTunnel(ifce, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "change-remote",
		ShortDescription: "Changes the remote address used in the tunnel for the provided vpn ip",
		Flags: func() (*flag.FlagSet, interface{}) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshChangeRemoteFlags{}
			fl.StringVar(&s.Address, "address", "", "The new remote address, ip:port")
			return fl, &s
		},
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshChangeRemote(ifce, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "close-tunnel",
		ShortDescription: "Closes a tunnel for the provided vpn ip",
		Flags: func() (*flag.FlagSet, interface{}) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshCloseTunnelFlags{}
			fl.BoolVar(&s.LocalOnly, "local-only", false, "Disables notifying the remote that the tunnel is shutting down")
			return fl, &s
		},
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshCloseTunnel(ifce, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "create-tunnel",
		ShortDescription: "Creates a tunnel for the provided vpn ip and address",
		Help:             "The lighthouses will be queried for real addresses but you can provide one as well.",
		Flags: func() (*flag.FlagSet, interface{}) {
			fl := flag.NewFlagSet("", flag.ContinueOnError)
			s := sshCreateTunnelFlags{}
			fl.StringVar(&s.Address, "address", "", "Optionally provide a real remote address, ip:port ")
			return fl, &s
		},
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshCreateTunnel(ifce, fs, a, w)
		},
	})

	ssh.RegisterCommand(&sshd.Command{
		Name:             "query-lighthouse",
		ShortDescription: "Query the lighthouses for the provided vpn ip",
		Help:             "This command is asynchronous. Only currently known udp ips will be printed.",
		Callback: func(fs interface{}, a []string, w sshd.StringWriter) error {
			return sshQueryLighthouse(ifce, fs, a, w)
		},
	})
}

func sshListHostMap(hostMap *HostMap, a interface{}, w sshd.StringWriter) error {
	fs, ok := a.(*sshListHostMapFlags)
	if !ok {
		return fmt.Errorf("flags not of type *sshListHostMapFlags")
	}

	type hostInfo struct {
		VpnIP          net.IP                  `json:"vpnIp"`
		LocalIndex     uint32                  `json:"localIndex"`
		RemoteIndex    uint32                  `json:"remoteIndex"`
		RemoteAddrs    []*udpAddr              `json:"remoteAddrs"`
		CachedPackets  int                     `json:"cachedPackets"`
		Cert           *cert.NebulaCertificate `json:"cert"`
		MessageCounter *uint64                 `json:"messageCounter"`
	}

	hostMap.RLock()
	hosts := make(map[uint32]hostInfo, len(hostMap.Hosts))
	for k, v := range hostMap.Hosts {
		info := hostInfo{
			VpnIP:         int2ip(v.hostId),
			LocalIndex:    v.localIndexId,
			RemoteIndex:   v.remoteIndexId,
			RemoteAddrs:   v.RemoteUDPAddrs(),
			CachedPackets: len(v.packetStore),
			Cert:          v.GetCert(),
		}
		if v.ConnectionState != nil {
			info.MessageCounter = v.ConnectionState.messageCounter
		}
		hosts[k] = info
	}
	hostMap.RUnlock()

	if fs.Json || fs.Pretty {
		js := json.NewEncoder(w.GetWriter())
		if fs.Pretty {
			js.SetIndent("", "    ")
		}

		err := js.Encode(hosts)
		if err != nil {
			return err
		}
	} else {
		for _, h := range hosts {
			err := w.WriteLine(fmt.Sprintf("%s: %s", h.VpnIP, h.RemoteAddrs))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func sshListLighthouseMap(lightHouse *LightHouse, a interface{}, w sshd.StringWriter) error {
	fs, ok := a.(*sshListHostMapFlags)
	if !ok {
		return fmt.Errorf("flags not of type *sshListHostMapFlags")
	}

	type lighthouseInfo struct {
		VpnIP net.IP   `json:"vpnIp"`
		Addrs []string `json:"addrs"`
	}

	lightHouse.RLock()
	lighthouses := make([]lighthouseInfo, 0, len(lightHouse.addrMap))
	for k, v := range lightHouse.addrMap {
		addrs := make([]string, 0, len(v))
		for _, addr := range v {
			addrs = append(addrs, addr.String())
		}
		info := lighthouseInfo{
			VpnIP: int2ip(k),
			Addrs: addrs,
		}
		lighthouses = append(lighthouses, info)
	}
	lightHouse.RUnlock()

	if fs.Json || fs.Pretty {
		js := json.NewEncoder(w.GetWriter())
		if fs.Pretty {
			js.SetIndent("", "    ")
		}

		err := js.Encode(lighthouses)
		if err != nil {
			return err
		}
	} else {
		for _, lighthouse := range lighthouses {
			err := w.WriteLine(fmt.Sprintf("%s: %s", lighthouse.VpnIP, lighthouse.Addrs))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func sshStartCpuProfile(fs interface{}, a []string, w sshd.StringWriter) error {
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

func sshVersion(ifce *Interface, fs interface{}, a []string, w sshd.StringWriter) error {
	return w.WriteLine(fmt.Sprintf("%s", ifce.version))
}

func sshQueryLighthouse(ifce *Interface, fs interface{}, a []string, w sshd.StringWriter) error {
	if len(a) == 0 {
		return w.WriteLine("No vpn ip was provided")
	}

	vpnIp := ip2int(net.ParseIP(a[0]))
	if vpnIp == 0 {
		return w.WriteLine(fmt.Sprintf("The provided vpn ip could not be parsed: %s", a[0]))
	}

	ips, _ := ifce.lightHouse.Query(vpnIp, ifce)
	return json.NewEncoder(w.GetWriter()).Encode(ips)
}

func sshCloseTunnel(ifce *Interface, fs interface{}, a []string, w sshd.StringWriter) error {
	flags, ok := fs.(*sshCloseTunnelFlags)
	if !ok {
		return fmt.Errorf("flags not of type *sshCloseTunnelFlags")
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn ip was provided")
	}

	vpnIp := ip2int(net.ParseIP(a[0]))
	if vpnIp == 0 {
		return w.WriteLine(fmt.Sprintf("The provided vpn ip could not be parsed: %s", a[0]))
	}

	hostInfo, err := ifce.hostMap.QueryVpnIP(uint32(vpnIp))
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn ip: %v", a[0]))
	}

	if !flags.LocalOnly {
		ifce.send(
			closeTunnel,
			0,
			hostInfo.ConnectionState,
			hostInfo,
			hostInfo.remote,
			[]byte{},
			make([]byte, 12, 12),
			make([]byte, mtu),
		)
	}

	ifce.closeTunnel(hostInfo)
	return w.WriteLine("Closed")
}

func sshCreateTunnel(ifce *Interface, fs interface{}, a []string, w sshd.StringWriter) error {
	flags, ok := fs.(*sshCreateTunnelFlags)
	if !ok {
		return fmt.Errorf("flags not of type *sshCreateTunnelFlags")
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn ip was provided")
	}

	vpnIp := ip2int(net.ParseIP(a[0]))
	if vpnIp == 0 {
		return w.WriteLine(fmt.Sprintf("The provided vpn ip could not be parsed: %s", a[0]))
	}

	hostInfo, _ := ifce.hostMap.QueryVpnIP(uint32(vpnIp))
	if hostInfo != nil {
		return w.WriteLine(fmt.Sprintf("Tunnel already exists"))
	}

	hostInfo, _ = ifce.handshakeManager.pendingHostMap.QueryVpnIP(uint32(vpnIp))
	if hostInfo != nil {
		return w.WriteLine(fmt.Sprintf("Tunnel already handshaking"))
	}

	var addr *udpAddr
	if flags.Address != "" {
		addr = NewUDPAddrFromString(flags.Address)
		if addr == nil {
			return w.WriteLine("Address could not be parsed")
		}
	}

	hostInfo = ifce.handshakeManager.AddVpnIP(vpnIp)
	if addr != nil {
		hostInfo.SetRemote(*addr)
	}
	ifce.getOrHandshake(vpnIp)

	return w.WriteLine("Created")
}

func sshChangeRemote(ifce *Interface, fs interface{}, a []string, w sshd.StringWriter) error {
	flags, ok := fs.(*sshChangeRemoteFlags)
	if !ok {
		return fmt.Errorf("flags not of type *sshChangeRemoteFlags")
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn ip was provided")
	}

	if flags.Address == "" {
		return w.WriteLine("No address was provided")
	}

	addr := NewUDPAddrFromString(flags.Address)
	if addr == nil {
		return w.WriteLine("Address could not be parsed")
	}

	vpnIp := ip2int(net.ParseIP(a[0]))
	if vpnIp == 0 {
		return w.WriteLine(fmt.Sprintf("The provided vpn ip could not be parsed: %s", a[0]))
	}

	hostInfo, err := ifce.hostMap.QueryVpnIP(uint32(vpnIp))
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn ip: %v", a[0]))
	}

	hostInfo.SetRemote(*addr)
	return w.WriteLine("Changed")
}

func sshGetHeapProfile(fs interface{}, a []string, w sshd.StringWriter) error {
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

func sshLogLevel(fs interface{}, a []string, w sshd.StringWriter) error {
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

func sshLogFormat(fs interface{}, a []string, w sshd.StringWriter) error {
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

func sshPrintCert(ifce *Interface, fs interface{}, a []string, w sshd.StringWriter) error {
	args, ok := fs.(*sshPrintCertFlags)
	if !ok {
		return fmt.Errorf("flags not of type *sshPrintCertFlags")
	}

	cert := ifce.certState.certificate
	if len(a) > 0 {
		vpnIp := ip2int(net.ParseIP(a[0]))
		if vpnIp == 0 {
			return w.WriteLine(fmt.Sprintf("The provided vpn ip could not be parsed: %s", a[0]))
		}

		hostInfo, err := ifce.hostMap.QueryVpnIP(uint32(vpnIp))
		if err != nil {
			return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn ip: %v", a[0]))
		}

		cert = hostInfo.GetCert()
	}

	if args.Json || args.Pretty {
		b, err := cert.MarshalJSON()
		if err != nil {
			//TODO: handle it
			return nil
		}

		if args.Pretty {
			buf := new(bytes.Buffer)
			err := json.Indent(buf, b, "", "    ")
			b = buf.Bytes()
			if err != nil {
				//TODO: handle it
				return nil
			}
		}

		return w.WriteBytes(b)
	}

	return w.WriteLine(cert.String())
}

func sshPrintTunnel(ifce *Interface, fs interface{}, a []string, w sshd.StringWriter) error {
	args, ok := fs.(*sshPrintTunnelFlags)
	if !ok {
		return fmt.Errorf("flags not of type *sshPrintTunnelFlags")
	}

	if len(a) == 0 {
		return w.WriteLine("No vpn ip was provided")
	}

	vpnIp := ip2int(net.ParseIP(a[0]))
	if vpnIp == 0 {
		return w.WriteLine(fmt.Sprintf("The provided vpn ip could not be parsed: %s", a[0]))
	}

	hostInfo, err := ifce.hostMap.QueryVpnIP(uint32(vpnIp))
	if err != nil {
		return w.WriteLine(fmt.Sprintf("Could not find tunnel for vpn ip: %v", a[0]))
	}

	enc := json.NewEncoder(w.GetWriter())
	if args.Pretty {
		enc.SetIndent("", "    ")
	}

	return enc.Encode(hostInfo)
}

func sshReload(fs interface{}, a []string, w sshd.StringWriter) error {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return w.WriteLine(err.Error())
	}
	err = p.Signal(syscall.SIGHUP)
	if err != nil {
		return w.WriteLine(err.Error())
	}
	return w.WriteLine("HUP sent")
}
