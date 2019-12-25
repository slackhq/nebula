package nebula

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
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

func Main(configPath string, configTest bool, buildVersion string, tunFd *int) error {

	l.Out = os.Stdout
	l.Formatter = &logrus.TextFormatter{
		FullTimestamp: true,
	}

	config := NewConfig()
	var err error
	if runtime.GOOS == "android" || runtime.GOOS == "ios" {
		err = config.LoadString(configPath)
	} else {
		err = config.Load(configPath)
	}
	if err != nil {
		l.WithError(err).Error("Failed to load config")
		time.Sleep(time.Minute * 1)
		return err
	}

	// Print the config if in test, the exit comes later
	if configTest {
		b, err := yaml.Marshal(config.Settings)
		if err != nil {
			l.Println(err)
			return err
		}
		l.Println(string(b))
	}

	err = configLogger(config)
	if err != nil {
		l.WithError(err).Error("Failed to configure the logger")
		return err
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
		l.WithError(err).Error("Failed to load ca from config")
		return err
	}
	l.WithField("fingerprints", trustedCAs.GetFingerprints()).Debug("Trusted CA fingerprints")

	cs, err := NewCertStateFromConfig(config)
	if err != nil {
		//The errors coming out of NewCertStateFromConfig are already nicely formatted
		l.WithError(err).Error("Failed to load certificate from config")
		return err
	}
	l.WithField("cert", cs.certificate).Debug("Client nebula certificate")

	fw, err := NewFirewallFromConfig(cs.certificate, config)
	if err != nil {
		l.WithError(err).Error("Error while loading firewall rules")
		return err
	}
	l.WithField("firewallHash", fw.GetRuleHash()).Info("Firewall started")

	// TODO: make sure mask is 4 bytes
	tunCidr := cs.certificate.Details.Ips[0]
	routes, err := parseRoutes(config, tunCidr)
	if err != nil {
		l.WithError(err).Error("Could not parse tun.routes")
		return err
	}
	unsafeRoutes, err := parseUnsafeRoutes(config, tunCidr)
	if err != nil {
		l.WithError(err).Error("Could not parse tun.unsafe_routes")
		return err
	}

	ssh, err := sshd.NewSSHServer(l.WithField("subsystem", "sshd"))
	wireSSHReload(ssh, config)
	if config.GetBool("sshd.enabled", false) {
		err = configSSH(ssh, config)
		if err != nil {
			l.WithError(err).Error("Error while configuring the sshd")
			return err
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// All non system modifying configuration consumption should live above this line
	// tun config, listeners, anything modifying the computer should be below
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	var tun *Tun
	if !configTest {
		if tunFd != nil {
			tun, err = newTunFromFd(
				*tunFd,
				tunCidr,
				config.GetInt("tun.mtu", DEFAULT_MTU),
				routes,
				unsafeRoutes,
				config.GetInt("tun.tx_queue", 500),
			)
		} else {
			tun, err = newTun(
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
		}
	}

	// set up our UDP listener
	udpQueues := config.GetInt("listen.routines", 1)
	var udpServer *udpConn

	if !configTest {
		udpServer, err = NewListener(config.GetString("listen.host", "0.0.0.0"), config.GetInt("listen.port", 0), udpQueues > 1)
		if err != nil {
			l.WithError(err).Error("Failed to open udp listener")
			return err
		}
		udpServer.reloadConfig(config)
	}

	// Set up my internal host map
	var preferredRanges []*net.IPNet
	rawPreferredRanges := config.GetStringSlice("preferred_ranges", []string{})
	// First, check if 'preferred_ranges' is set and fallback to 'local_range'
	if len(rawPreferredRanges) > 0 {
		for _, rawPreferredRange := range rawPreferredRanges {
			_, preferredRange, err := net.ParseCIDR(rawPreferredRange)
			if err != nil {
				l.WithError(err).Error("Failed to parse preferred ranges")
				return err
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
			l.WithError(err).Error("Failed to parse local range")
			return err
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
	hostMap.metricsEnabled = config.GetBool("stats.message_metrics", false)

	l.WithField("network", hostMap.vpnCIDR).WithField("preferredRanges", hostMap.preferredRanges).Info("Main HostMap created")

	/*
		config.SetDefault("promoter.interval", 10)
		go hostMap.Promoter(config.GetInt("promoter.interval"))
	*/

	punchy := NewPunchyFromConfig(config)
	if punchy.Punch && !configTest {
		l.Info("UDP hole punching enabled")
		go hostMap.Punchy(udpServer)
	}

	port := config.GetInt("listen.port", 0)
	// If port is dynamic, discover it
	if port == 0 && !configTest {
		uPort, err := udpServer.LocalAddr()
		if err != nil {
			l.WithError(err).Error("Failed to get listening port")
			return err
		}
		port = int(uPort.Port)
	}

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
			l.WithField("host", host).Errorf("Unable to parse lighthouse host entry %v", i+1)
		}
		if !tunCidr.Contains(ip) {
			l.WithField("vpnIp", ip).WithField("network", tunCidr.String()).Fatalf("lighthouse host is not in our subnet, invalid")
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
		punchy.Respond,
		punchy.Delay,
		config.GetBool("stats.lighthouse_metrics", false),
	)

	remoteAllowList, err := config.GetAllowList("lighthouse.remote_allow_list", false)
	if err != nil {
		l.WithError(err).Fatal("Invalid lighthouse.remote_allow_list")
	}
	lightHouse.SetRemoteAllowList(remoteAllowList)

	localAllowList, err := config.GetAllowList("lighthouse.local_allow_list", true)
	if err != nil {
		l.WithError(err).Fatal("Invalid lighthouse.local_allow_list")
	}
	lightHouse.SetLocalAllowList(localAllowList)

	//TODO: Move all of this inside functions in lighthouse.go
	for k, v := range config.GetMap("static_host_map", map[interface{}]interface{}{}) {
		vpnIp := net.ParseIP(fmt.Sprintf("%v", k))
		if !tunCidr.Contains(vpnIp) {
			l.WithField("vpnIp", vpnIp).WithField("network", tunCidr.String()).Fatalf("static_host_map key is not in our subnet, invalid")
		}
		vals, ok := v.([]interface{})
		if ok {
			for _, v := range vals {
				parts := strings.Split(fmt.Sprintf("%v", v), ":")
				addr, err := net.ResolveIPAddr("ip", parts[0])
				if err == nil {
					ip := addr.IP
					port, err := strconv.Atoi(parts[1])
					if err != nil {
						l.Errorf("Static host address for %s could not be parsed: %s", vpnIp, v)
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
					l.Errorf("Static host address for %s could not be parsed: %s", vpnIp, v)
				}
				lightHouse.AddRemote(ip2int(vpnIp), NewUDPAddr(ip2int(ip), uint16(port)), true)
			}
		}
	}

	err = lightHouse.ValidateLHStaticEntries()
	if err != nil {
		l.WithError(err).Error("Lighthouse unreachable")
	}

	var messageMetrics *MessageMetrics
	if config.GetBool("stats.message_metrics", false) {
		messageMetrics = newMessageMetrics()
	} else {
		messageMetrics = newMessageMetricsOnlyRecvError()
	}

	handshakeConfig := HandshakeConfig{
		tryInterval:  config.GetDuration("handshakes.try_interval", DefaultHandshakeTryInterval),
		retries:      config.GetInt("handshakes.retries", DefaultHandshakeRetries),
		waitRotation: config.GetInt("handshakes.wait_rotation", DefaultHandshakeWaitRotation),

		messageMetrics: messageMetrics,
	}

	handshakeManager := NewHandshakeManager(tunCidr, preferredRanges, hostMap, lightHouse, udpServer, handshakeConfig)

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
		MessageMetrics:          messageMetrics,
	}

	switch ifConfig.Cipher {
	case "aes":
		noiseEndianness = binary.BigEndian
	case "chachapoly":
		noiseEndianness = binary.LittleEndian
	default:
		l.Errorf("Unknown cipher: %v", ifConfig.Cipher)
	}
	
	var ifce *Interface
	if !configTest {
		ifce, err = NewInterface(ifConfig)
		if err != nil {
			l.WithError(err).Error("Failed to initialize interface")
			return err
		}

		ifce.RegisterConfigChangeCallbacks(config)

		go handshakeManager.Run(ifce)
		go lightHouse.LhUpdateWorker(ifce)
	}

	err = startStats(config, configTest)
	if err != nil {
		l.WithError(err).Error("Failed to start stats emitter")
	}

	if configTest {
		os.Exit(0)
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
	return nil
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
}
