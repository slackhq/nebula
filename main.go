package nebula

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/sshd"
	"gopkg.in/yaml.v2"
)

var l = logrus.New()

type m map[string]interface{}

func Main(configPath string, configTest bool, buildVersion string) {
	l.Out = os.Stdout
	l.Formatter = &logrus.TextFormatter{
		FullTimestamp: true,
	}

	config := NewConfig()
	err := config.Load(configPath)
	if err != nil {
		l.WithError(err).Error("Failed to load config")
		os.Exit(1)
	}

	// Print the config if in test, the exit comes later
	if configTest {
		b, err := yaml.Marshal(config.Settings)
		if err != nil {
			l.Println(err)
			os.Exit(1)
		}
		l.Println(string(b))
	}

	err = configLogger(config)
	if err != nil {
		l.WithError(err).Error("Failed to configure the logger")
	}

	config.RegisterReloadCallback(func(c *Config) {
		err := configLogger(c)
		if err != nil {
			l.WithError(err).Error("Failed to configure the logger")
		}
	})

	// trustedCAs is currently a global, so loadCA operates on that global directly
	trustedCAs, err = loadCAFromConfig(config)
	if err != nil {
		//The errors coming out of loadCA are already nicely formatted
		l.WithError(err).Fatal("Failed to load ca from config")
	}
	l.WithField("fingerprints", trustedCAs.GetFingerprints()).Debug("Trusted CA fingerprints")

	cs, err := NewCertStateFromConfig(config)
	if err != nil {
		//The errors coming out of NewCertStateFromConfig are already nicely formatted
		l.WithError(err).Fatal("Failed to load certificate from config")
	}
	l.WithField("cert", cs.certificate).Debug("Client nebula certificate")

	fw, err := NewFirewallFromConfig(cs.certificate, config)
	if err != nil {
		l.WithError(err).Fatal("Error while loading firewall rules")
	}
	l.WithField("firewallHash", fw.GetRuleHash()).Info("Firewall started")

	var tunCidr *net.IPNet
	listenIP := config.GetString("listen.host", "0.0.0.0")
	if listenIP != "0.0.0.0" {
		ip, ipNet, err := net.ParseCIDR(listenIP)
		if err != nil {
			l.WithError(err).Fatal("Error while configuring listening IP")
		}
		for _, i := range cs.certificate.Details.Ips {
			ipNet.IP = ip
			if i.IP.Equal(ipNet.IP) {
				tunCidr = ipNet
			}
		}
	} else {
		tunCidr = cs.certificate.Details.Ips[0]
	}

	routes, err := parseRoutes(config, tunCidr)
	if err != nil {
		l.WithError(err).Fatal("Could not parse tun.routes")
	}
	unsafeRoutes, err := parseUnsafeRoutes(config, tunCidr)
	if err != nil {
		l.WithError(err).Fatal("Could not parse tun.unsafe_routes")
	}

	ssh, err := sshd.NewSSHServer(l.WithField("subsystem", "sshd"))
	wireSSHReload(ssh, config)
	if config.GetBool("sshd.enabled", false) {
		err = configSSH(ssh, config)
		if err != nil {
			l.WithError(err).Fatal("Error while configuring the sshd")
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// All non system modifying configuration consumption should live above this line
	// tun config, listeners, anything modifying the computer should be below
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	if configTest {
		os.Exit(0)
	}

	config.CatchHUP()

	// set up our tun dev
	tun, err := newTun(
		config.GetString("tun.dev", ""),
		tunCidr,
		config.GetInt("tun.mtu", DEFAULT_MTU),
		routes,
		unsafeRoutes,
		config.GetInt("tun.tx_queue", 500),
	)
	if err != nil {
		l.WithError(err).Fatal("Failed to get a tun/tap device")
	}

	// set up our UDP listener
	udpQueues := config.GetInt("listen.routines", 1)
	udpServer, err := NewListener(config.GetString("listen.host", "0.0.0.0"), config.GetInt("listen.port", 0), udpQueues > 1)
	if err != nil {
		l.WithError(err).Fatal("Failed to open udp listener")
	}
	udpServer.reloadConfig(config)

	// Set up my internal host map
	var preferredRanges []*net.IPNet
	rawPreferredRanges := config.GetStringSlice("preferred_ranges", []string{})
	// First, check if 'preferred_ranges' is set and fallback to 'local_range'
	if len(rawPreferredRanges) > 0 {
		for _, rawPreferredRange := range rawPreferredRanges {
			_, preferredRange, err := net.ParseCIDR(rawPreferredRange)
			if err != nil {
				l.WithError(err).Fatal("Failed to parse preferred ranges")
			}
			preferredRanges = append(preferredRanges, preferredRange)
		}
	}

	// local_range was superseded by preferred_ranges. If it is still present,
	// merge the local_range setting into preferred_ranges. We will probably
	// deprecate local_range and remove in the future.
	rawLocalRange := config.GetString("local_range", "")
	if rawLocalRange != "" {
		_, localRange, err := net.ParseCIDR(rawLocalRange)
		if err != nil {
			l.WithError(err).Fatal("Failed to parse local range")
		}

		// Check if the entry for local_range was already specified in
		// preferred_ranges. Don't put it into the slice twice if so.
		var found bool
		for _, r := range preferredRanges {
			if r.String() == localRange.String() {
				found = true
				break
			}
		}
		if !found {
			preferredRanges = append(preferredRanges, localRange)
		}
	}

	hostMap := NewHostMap("main", tunCidr, preferredRanges)
	hostMap.SetDefaultRoute(ip2int(net.ParseIP(config.GetString("default_route", "0.0.0.0"))))
	hostMap.addUnsafeRoutes(&unsafeRoutes)

	l.WithField("network", hostMap.vpnCIDR).WithField("preferredRanges", hostMap.preferredRanges).Info("Main HostMap created")

	/*
		config.SetDefault("promoter.interval", 10)
		go hostMap.Promoter(config.GetInt("promoter.interval"))
	*/

	punchy := config.GetBool("punchy", false)
	if punchy == true {
		l.Info("UDP hole punching enabled")
		go hostMap.Punchy(udpServer)
	}

	port := config.GetInt("listen.port", 0)
	// If port is dynamic, discover it
	if port == 0 {
		uPort, err := udpServer.LocalAddr()
		if err != nil {
			l.WithError(err).Fatal("Failed to get listening port")
		}
		port = int(uPort.Port)
	}

	punchBack := config.GetBool("punch_back", false)
	amLighthouse := config.GetBool("lighthouse.am_lighthouse", false)

	// warn if am_lighthouse is enabled but upstream lighthouses exists
	rawLighthouseHosts := config.GetStringSlice("lighthouse.hosts", []string{})
	if amLighthouse && len(rawLighthouseHosts) != 0 {
		l.Warn("lighthouse.am_lighthouse enabled on node but upstream lighthouses exist in config")
	}

	lighthouseHosts := make([]uint32, len(rawLighthouseHosts))
	for i, host := range rawLighthouseHosts {
		ip := net.ParseIP(host)
		if ip == nil {
			l.WithField("host", host).Fatalf("Unable to parse lighthouse host entry %v", i+1)
		}
		lighthouseHosts[i] = ip2int(ip)
	}

	lightHouse := NewLightHouse(
		amLighthouse,
		ip2int(tunCidr.IP),
		lighthouseHosts,
		//TODO: change to a duration
		config.GetInt("lighthouse.interval", 10),
		port,
		udpServer,
		punchBack,
	)

	//TODO: Move all of this inside functions in lighthouse.go
	for k, v := range config.GetMap("static_host_map", map[interface{}]interface{}{}) {
		vpnIp := net.ParseIP(fmt.Sprintf("%v", k))
		vals, ok := v.([]interface{})
		if ok {
			for _, v := range vals {
				parts := strings.Split(fmt.Sprintf("%v", v), ":")
				addr, err := net.ResolveIPAddr("ip", parts[0])
				if err == nil {
					ip := addr.IP
					port, err := strconv.Atoi(parts[1])
					if err != nil {
						l.Fatalf("Static host address for %s could not be parsed: %s", vpnIp, v)
					}
					lightHouse.AddRemote(ip2int(vpnIp), NewUDPAddr(ip2int(ip), uint16(port)), true)
				}
			}
		} else {
			//TODO: make this all a helper
			parts := strings.Split(fmt.Sprintf("%v", v), ":")
			addr, err := net.ResolveIPAddr("ip", parts[0])
			if err == nil {
				ip := addr.IP
				port, err := strconv.Atoi(parts[1])
				if err != nil {
					l.Fatalf("Static host address for %s could not be parsed: %s", vpnIp, v)
				}
				lightHouse.AddRemote(ip2int(vpnIp), NewUDPAddr(ip2int(ip), uint16(port)), true)
			}
		}
	}

	err = lightHouse.ValidateLHStaticEntries()
	if err != nil {
		l.WithError(err).Error("Lighthouse unreachable")
	}

	handshakeManager := NewHandshakeManager(tunCidr, preferredRanges, hostMap, lightHouse, udpServer)

	//TODO: These will be reused for psk
	//handshakeMACKey := config.GetString("handshake_mac.key", "")
	//handshakeAcceptedMACKeys := config.GetStringSlice("handshake_mac.accepted_keys", []string{})

	serveDns := config.GetBool("lighthouse.serve_dns", false)
	checkInterval := config.GetInt("timers.connection_alive_interval", 5)
	pendingDeletionInterval := config.GetInt("timers.pending_deletion_interval", 10)
	ifConfig := &InterfaceConfig{
		HostMap:                 hostMap,
		Inside:                  tun,
		Outside:                 udpServer,
		certState:               cs,
		Cipher:                  config.GetString("cipher", "aes"),
		Firewall:                fw,
		ServeDns:                serveDns,
		HandshakeManager:        handshakeManager,
		lightHouse:              lightHouse,
		checkInterval:           checkInterval,
		pendingDeletionInterval: pendingDeletionInterval,
		DropLocalBroadcast:      config.GetBool("tun.drop_local_broadcast", false),
		DropMulticast:           config.GetBool("tun.drop_multicast", false),
		UDPBatchSize:            config.GetInt("listen.batch", 64),
	}

	switch ifConfig.Cipher {
	case "aes":
		noiseEndiannes = binary.BigEndian
	case "chachapoly":
		noiseEndiannes = binary.LittleEndian
	default:
		l.Fatalf("Unknown cipher: %v", ifConfig.Cipher)
	}

	ifce, err := NewInterface(ifConfig)
	if err != nil {
		l.WithError(err).Fatal("Failed to initialize interface")
	}

	ifce.RegisterConfigChangeCallbacks(config)

	go handshakeManager.Run(ifce)
	go lightHouse.LhUpdateWorker(ifce)

	err = startStats(config)
	if err != nil {
		l.WithError(err).Fatal("Failed to start stats emitter")
	}

	//TODO: check if we _should_ be emitting stats
	go ifce.emitStats(config.GetDuration("stats.interval", time.Second*10))

	attachCommands(ssh, hostMap, handshakeManager.pendingHostMap, lightHouse, ifce)
	ifce.Run(config.GetInt("tun.routines", 1), udpQueues, buildVersion)

	// Start DNS server last to allow using the nebula IP as lighthouse.dns.host
	if amLighthouse && serveDns {
		l.Debugln("Starting dns server")
		go dnsMain(hostMap, config)
	}

	// Just sit here and be friendly, main thread.
	shutdownBlock(ifce)
}

func shutdownBlock(ifce *Interface) {
	var sigChan = make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)

	sig := <-sigChan
	l.WithField("signal", sig).Info("Caught signal, shutting down")

	//TODO: stop tun and udp routines, the lock on hostMap does effectively does that though
	//TODO: this is probably better as a function in ConnectionManager or HostMap directly
	ifce.hostMap.Lock()
	for _, h := range ifce.hostMap.Hosts {
		if h.ConnectionState.ready {
			ifce.send(closeTunnel, 0, h.ConnectionState, h, h.remote, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
			l.WithField("vpnIp", IntIp(h.hostId)).WithField("udpAddr", h.remote).
				Debug("Sending close tunnel message")
		}
	}
	ifce.hostMap.Unlock()

	l.WithField("signal", sig).Info("Goodbye")
	os.Exit(0)
}
