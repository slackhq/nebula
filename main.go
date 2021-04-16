package nebula

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/sshd"
	"gopkg.in/yaml.v2"
)

type m map[string]interface{}

func Main(config *Config, configTest bool, buildVersion string, logger *logrus.Logger, tunFd *int) (*Control, error) {
	l := logger
	l.Formatter = &logrus.TextFormatter{
		FullTimestamp: true,
	}

	// Print the config if in test, the exit comes later
	if configTest {
		b, err := yaml.Marshal(config.Settings)
		if err != nil {
			return nil, err
		}

		// Print the final config
		l.Println(string(b))
	}

	err := configLogger(config)
	if err != nil {
		return nil, NewContextualError("Failed to configure the logger", nil, err)
	}

	config.RegisterReloadCallback(func(c *Config) {
		err := configLogger(c)
		if err != nil {
			l.WithError(err).Error("Failed to configure the logger")
		}
	})

	caPool, err := loadCAFromConfig(l, config)
	if err != nil {
		//The errors coming out of loadCA are already nicely formatted
		return nil, NewContextualError("Failed to load ca from config", nil, err)
	}
	l.WithField("fingerprints", caPool.GetFingerprints()).Debug("Trusted CA fingerprints")

	cs, err := NewCertStateFromConfig(config)
	if err != nil {
		//The errors coming out of NewCertStateFromConfig are already nicely formatted
		return nil, NewContextualError("Failed to load certificate from config", nil, err)
	}
	l.WithField("cert", cs.certificate).Debug("Client nebula certificate")

	fw, err := NewFirewallFromConfig(l, cs.certificate, config)
	if err != nil {
		return nil, NewContextualError("Error while loading firewall rules", nil, err)
	}
	l.WithField("firewallHash", fw.GetRuleHash()).Info("Firewall started")

	// TODO: make sure mask is 4 bytes
	tunCidr := cs.certificate.Details.Ips[0]
	routes, err := parseRoutes(config, tunCidr)
	if err != nil {
		return nil, NewContextualError("Could not parse tun.routes", nil, err)
	}
	unsafeRoutes, err := parseUnsafeRoutes(config, tunCidr)
	if err != nil {
		return nil, NewContextualError("Could not parse tun.unsafe_routes", nil, err)
	}

	ssh, err := sshd.NewSSHServer(l.WithField("subsystem", "sshd"))
	wireSSHReload(l, ssh, config)
	var sshStart func()
	if config.GetBool("sshd.enabled", false) {
		sshStart, err = configSSH(l, ssh, config)
		if err != nil {
			return nil, NewContextualError("Error while configuring the sshd", nil, err)
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// All non system modifying configuration consumption should live above this line
	// tun config, listeners, anything modifying the computer should be below
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	var routines int

	// If `routines` is set, use that and ignore the specific values
	if routines = config.GetInt("routines", 0); routines != 0 {
		if routines < 1 {
			routines = 1
		}
		if routines > 1 {
			l.WithField("routines", routines).Info("Using multiple routines")
		}
	} else {
		// deprecated and undocumented
		tunQueues := config.GetInt("tun.routines", 1)
		udpQueues := config.GetInt("listen.routines", 1)
		if tunQueues > udpQueues {
			routines = tunQueues
		} else {
			routines = udpQueues
		}
		if routines != 1 {
			l.WithField("routines", routines).Warn("Setting tun.routines and listen.routines is deprecated. Use `routines` instead")
		}
	}

	// EXPERIMENTAL
	// Intentionally not documented yet while we do more testing and determine
	// a good default value.
	conntrackCacheTimeout := config.GetDuration("firewall.conntrack.routine_cache_timeout", 0)
	if routines > 1 && !config.IsSet("firewall.conntrack.routine_cache_timeout") {
		// Use a different default if we are running with multiple routines
		conntrackCacheTimeout = 1 * time.Second
	}
	if conntrackCacheTimeout > 0 {
		l.WithField("duration", conntrackCacheTimeout).Info("Using routine-local conntrack cache")
	}

	var tun Inside
	if !configTest {
		config.CatchHUP()

		switch {
		case config.GetBool("tun.disabled", false):
			tun = newDisabledTun(tunCidr, config.GetInt("tun.tx_queue", 500), config.GetBool("stats.message_metrics", false), l)
		case tunFd != nil:
			tun, err = newTunFromFd(
				l,
				*tunFd,
				tunCidr,
				config.GetInt("tun.mtu", DEFAULT_MTU),
				routes,
				unsafeRoutes,
				config.GetInt("tun.tx_queue", 500),
			)
		default:
			tun, err = newTun(
				l,
				config.GetString("tun.dev", ""),
				tunCidr,
				config.GetInt("tun.mtu", DEFAULT_MTU),
				routes,
				unsafeRoutes,
				config.GetInt("tun.tx_queue", 500),
				routines > 1,
			)
		}

		if err != nil {
			return nil, NewContextualError("Failed to get a tun/tap device", nil, err)
		}
	}

	// set up our UDP listener
	udpConns := make([]*udpConn, routines)
	port := config.GetInt("listen.port", 0)

	if !configTest {
		for i := 0; i < routines; i++ {
			udpServer, err := NewListener(l, config.GetString("listen.host", "0.0.0.0"), port, routines > 1)
			if err != nil {
				return nil, NewContextualError("Failed to open udp listener", m{"queue": i}, err)
			}
			udpServer.reloadConfig(config)
			udpConns[i] = udpServer

			// If port is dynamic, discover it
			if port == 0 {
				uPort, err := udpServer.LocalAddr()
				if err != nil {
					return nil, NewContextualError("Failed to get listening port", nil, err)
				}
				port = int(uPort.Port)
			}
		}
	}

	// Set up my internal host map
	var preferredRanges []*net.IPNet
	rawPreferredRanges := config.GetStringSlice("preferred_ranges", []string{})
	// First, check if 'preferred_ranges' is set and fallback to 'local_range'
	if len(rawPreferredRanges) > 0 {
		for _, rawPreferredRange := range rawPreferredRanges {
			_, preferredRange, err := net.ParseCIDR(rawPreferredRange)
			if err != nil {
				return nil, NewContextualError("Failed to parse preferred ranges", nil, err)
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
			return nil, NewContextualError("Failed to parse local_range", nil, err)
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

	hostMap := NewHostMap(l, "main", tunCidr, preferredRanges)

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
		go hostMap.Punchy(udpConns[0])
	}

	amLighthouse := config.GetBool("lighthouse.am_lighthouse", false)

	// fatal if am_lighthouse is enabled but we are using an ephemeral port
	if amLighthouse && (config.GetInt("listen.port", 0) == 0) {
		return nil, NewContextualError("lighthouse.am_lighthouse enabled on node but no port number is set in config", nil, nil)
	}

	// warn if am_lighthouse is enabled but upstream lighthouses exists
	rawLighthouseHosts := config.GetStringSlice("lighthouse.hosts", []string{})
	if amLighthouse && len(rawLighthouseHosts) != 0 {
		l.Warn("lighthouse.am_lighthouse enabled on node but upstream lighthouses exist in config")
	}

	lighthouseHosts := make([]uint32, len(rawLighthouseHosts))
	for i, host := range rawLighthouseHosts {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, NewContextualError("Unable to parse lighthouse host entry", m{"host": host, "entry": i + 1}, nil)
		}
		if !tunCidr.Contains(ip) {
			return nil, NewContextualError("lighthouse host is not in our subnet, invalid", m{"vpnIp": ip, "network": tunCidr.String()}, nil)
		}
		lighthouseHosts[i] = ip2int(ip)
	}

	lightHouse := NewLightHouse(
		l,
		amLighthouse,
		tunCidr,
		lighthouseHosts,
		//TODO: change to a duration
		config.GetInt("lighthouse.interval", 10),
		uint32(port),
		udpConns[0],
		punchy.Respond,
		punchy.Delay,
		config.GetBool("stats.lighthouse_metrics", false),
	)

	remoteAllowList, err := config.GetAllowList("lighthouse.remote_allow_list", false)
	if err != nil {
		return nil, NewContextualError("Invalid lighthouse.remote_allow_list", nil, err)
	}
	lightHouse.SetRemoteAllowList(remoteAllowList)

	localAllowList, err := config.GetAllowList("lighthouse.local_allow_list", true)
	if err != nil {
		return nil, NewContextualError("Invalid lighthouse.local_allow_list", nil, err)
	}
	lightHouse.SetLocalAllowList(localAllowList)

	//TODO: Move all of this inside functions in lighthouse.go
	for k, v := range config.GetMap("static_host_map", map[interface{}]interface{}{}) {
		vpnIp := net.ParseIP(fmt.Sprintf("%v", k))
		if !tunCidr.Contains(vpnIp) {
			return nil, NewContextualError("static_host_map key is not in our subnet, invalid", m{"vpnIp": vpnIp, "network": tunCidr.String()}, nil)
		}
		vals, ok := v.([]interface{})
		if ok {
			for _, v := range vals {
				ip, port, err := parseIPAndPort(fmt.Sprintf("%v", v))
				if err != nil {
					return nil, NewContextualError("Static host address could not be parsed", m{"vpnIp": vpnIp}, err)
				}
				lightHouse.AddStaticRemote(ip2int(vpnIp), NewUDPAddr(ip, port))
			}
		} else {
			ip, port, err := parseIPAndPort(fmt.Sprintf("%v", v))
			if err != nil {
				return nil, NewContextualError("Static host address could not be parsed", m{"vpnIp": vpnIp}, err)
			}
			lightHouse.AddStaticRemote(ip2int(vpnIp), NewUDPAddr(ip, port))
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
		tryInterval:   config.GetDuration("handshakes.try_interval", DefaultHandshakeTryInterval),
		retries:       config.GetInt("handshakes.retries", DefaultHandshakeRetries),
		triggerBuffer: config.GetInt("handshakes.trigger_buffer", DefaultHandshakeTriggerBuffer),

		messageMetrics: messageMetrics,
	}

	handshakeManager := NewHandshakeManager(l, tunCidr, preferredRanges, hostMap, lightHouse, udpConns[0], handshakeConfig)
	lightHouse.handshakeTrigger = handshakeManager.trigger

	//TODO: These will be reused for psk
	//handshakeMACKey := config.GetString("handshake_mac.key", "")
	//handshakeAcceptedMACKeys := config.GetStringSlice("handshake_mac.accepted_keys", []string{})

	serveDns := false
	if config.GetBool("lighthouse.serve_dns", false) {
		if config.GetBool("lighthouse.am_lighthouse", false) {
			serveDns = true
		} else {
			l.Warn("DNS server refusing to run because this host is not a lighthouse.")
		}
	}

	checkInterval := config.GetInt("timers.connection_alive_interval", 5)
	pendingDeletionInterval := config.GetInt("timers.pending_deletion_interval", 10)
	ifConfig := &InterfaceConfig{
		HostMap:                 hostMap,
		Inside:                  tun,
		Outside:                 udpConns[0],
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
		routines:                routines,
		MessageMetrics:          messageMetrics,
		version:                 buildVersion,
		caPool:                  caPool,

		ConntrackCacheTimeout: conntrackCacheTimeout,
		l:                     l,
	}

	switch ifConfig.Cipher {
	case "aes":
		noiseEndianness = binary.BigEndian
	case "chachapoly":
		noiseEndianness = binary.LittleEndian
	default:
		return nil, fmt.Errorf("unknown cipher: %v", ifConfig.Cipher)
	}

	var ifce *Interface
	if !configTest {
		ifce, err = NewInterface(ifConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize interface: %s", err)
		}

		// TODO: Better way to attach these, probably want a new interface in InterfaceConfig
		// I don't want to make this initial commit too far-reaching though
		ifce.writers = udpConns

		ifce.RegisterConfigChangeCallbacks(config)

		go handshakeManager.Run(ifce)
		go lightHouse.LhUpdateWorker(ifce)
	}

	statsStart, err := startStats(l, config, buildVersion, configTest)
	if err != nil {
		return nil, NewContextualError("Failed to start stats emitter", nil, err)
	}

	if configTest {
		return nil, nil
	}

	//TODO: check if we _should_ be emitting stats
	go ifce.emitStats(config.GetDuration("stats.interval", time.Second*10))

	attachCommands(l, ssh, hostMap, handshakeManager.pendingHostMap, lightHouse, ifce)

	// Start DNS server last to allow using the nebula IP as lighthouse.dns.host
	var dnsStart func()
	if amLighthouse && serveDns {
		l.Debugln("Starting dns server")
		dnsStart = dnsMain(l, hostMap, config)
	}

	return &Control{ifce, l, sshStart, statsStart, dnsStart}, nil
}
