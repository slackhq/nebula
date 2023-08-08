package nebula

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/sshd"
	"github.com/slackhq/nebula/udp"
	"github.com/slackhq/nebula/util"
	"gopkg.in/yaml.v2"
)

type m map[string]interface{}

func Main(c *config.C, configTest bool, buildVersion string, logger *logrus.Logger, tunFd *int) (retcon *Control, reterr error) {
	ctx, cancel := context.WithCancel(context.Background())
	// Automatically cancel the context if Main returns an error, to signal all created goroutines to quit.
	defer func() {
		if reterr != nil {
			cancel()
		}
	}()

	l := logger
	l.Formatter = &logrus.TextFormatter{
		FullTimestamp: true,
	}

	// Print the config if in test, the exit comes later
	if configTest {
		b, err := yaml.Marshal(c.Settings)
		if err != nil {
			return nil, err
		}

		// Print the final config
		l.Println(string(b))
	}

	err := configLogger(l, c)
	if err != nil {
		return nil, util.NewContextualError("Failed to configure the logger", nil, err)
	}

	c.RegisterReloadCallback(func(c *config.C) {
		err := configLogger(l, c)
		if err != nil {
			l.WithError(err).Error("Failed to configure the logger")
		}
	})

	caPool, err := loadCAFromConfig(l, c)
	if err != nil {
		//The errors coming out of loadCA are already nicely formatted
		return nil, util.NewContextualError("Failed to load ca from config", nil, err)
	}
	l.WithField("fingerprints", caPool.GetFingerprints()).Debug("Trusted CA fingerprints")

	cs, err := NewCertStateFromConfig(c)
	if err != nil {
		//The errors coming out of NewCertStateFromConfig are already nicely formatted
		return nil, util.NewContextualError("Failed to load certificate from config", nil, err)
	}
	l.WithField("cert", cs.certificate).Debug("Client nebula certificate")

	fw, err := NewFirewallFromConfig(l, cs.certificate, c)
	if err != nil {
		return nil, util.NewContextualError("Error while loading firewall rules", nil, err)
	}
	l.WithField("firewallHash", fw.GetRuleHash()).Info("Firewall started")

	// TODO: make sure mask is 4 bytes
	tunCidr := cs.certificate.Details.Ips[0]

	ssh, err := sshd.NewSSHServer(l.WithField("subsystem", "sshd"))
	wireSSHReload(l, ssh, c)
	var sshStart func()
	if c.GetBool("sshd.enabled", false) {
		sshStart, err = configSSH(l, ssh, c)
		if err != nil {
			return nil, util.NewContextualError("Error while configuring the sshd", nil, err)
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// All non system modifying configuration consumption should live above this line
	// tun config, listeners, anything modifying the computer should be below
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	var routines int

	// If `routines` is set, use that and ignore the specific values
	if routines = c.GetInt("routines", 0); routines != 0 {
		if routines < 1 {
			routines = 1
		}
		if routines > 1 {
			l.WithField("routines", routines).Info("Using multiple routines")
		}
	} else {
		// deprecated and undocumented
		tunQueues := c.GetInt("tun.routines", 1)
		udpQueues := c.GetInt("listen.routines", 1)
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
	conntrackCacheTimeout := c.GetDuration("firewall.conntrack.routine_cache_timeout", 0)
	if routines > 1 && !c.IsSet("firewall.conntrack.routine_cache_timeout") {
		// Use a different default if we are running with multiple routines
		conntrackCacheTimeout = 1 * time.Second
	}
	if conntrackCacheTimeout > 0 {
		l.WithField("duration", conntrackCacheTimeout).Info("Using routine-local conntrack cache")
	}

	var tun overlay.Device
	if !configTest {
		c.CatchHUP(ctx)

		tun, err = overlay.NewDeviceFromConfig(c, l, tunCidr, tunFd, routines)
		if err != nil {
			return nil, util.NewContextualError("Failed to get a tun/tap device", nil, err)
		}

		defer func() {
			if reterr != nil {
				tun.Close()
			}
		}()
	}

	// set up our UDP listener
	udpConns := make([]udp.Conn, routines)
	port := c.GetInt("listen.port", 0)

	if !configTest {
		rawListenHost := c.GetString("listen.host", "0.0.0.0")
		var listenHost *net.IPAddr
		if rawListenHost == "[::]" {
			// Old guidance was to provide the literal `[::]` in `listen.host` but that won't resolve.
			listenHost = &net.IPAddr{IP: net.IPv6zero}

		} else {
			listenHost, err = net.ResolveIPAddr("ip", rawListenHost)
			if err != nil {
				return nil, util.NewContextualError("Failed to resolve listen.host", nil, err)
			}
		}

		for i := 0; i < routines; i++ {
			udpServer, err := udp.NewListener(l, listenHost.IP, port, routines > 1, c.GetInt("listen.batch", 64))
			if err != nil {
				return nil, util.NewContextualError("Failed to open udp listener", m{"queue": i}, err)
			}
			udpServer.ReloadConfig(c)
			udpConns[i] = udpServer
		}
	}

	// Set up my internal host map
	var preferredRanges []*net.IPNet
	rawPreferredRanges := c.GetStringSlice("preferred_ranges", []string{})
	// First, check if 'preferred_ranges' is set and fallback to 'local_range'
	if len(rawPreferredRanges) > 0 {
		for _, rawPreferredRange := range rawPreferredRanges {
			_, preferredRange, err := net.ParseCIDR(rawPreferredRange)
			if err != nil {
				return nil, util.NewContextualError("Failed to parse preferred ranges", nil, err)
			}
			preferredRanges = append(preferredRanges, preferredRange)
		}
	}

	// local_range was superseded by preferred_ranges. If it is still present,
	// merge the local_range setting into preferred_ranges. We will probably
	// deprecate local_range and remove in the future.
	rawLocalRange := c.GetString("local_range", "")
	if rawLocalRange != "" {
		_, localRange, err := net.ParseCIDR(rawLocalRange)
		if err != nil {
			return nil, util.NewContextualError("Failed to parse local_range", nil, err)
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

	hostMap := NewHostMap(l, tunCidr, preferredRanges)
	hostMap.metricsEnabled = c.GetBool("stats.message_metrics", false)

	l.
		WithField("network", hostMap.vpnCIDR.String()).
		WithField("preferredRanges", hostMap.preferredRanges).
		Info("Main HostMap created")

	punchy := NewPunchyFromConfig(l, c)
	lightHouse, err := NewLightHouseFromConfig(ctx, l, c, tunCidr, udpConns[0], punchy)
	switch {
	case errors.As(err, &util.ContextualError{}):
		return nil, err
	case err != nil:
		return nil, util.NewContextualError("Failed to initialize lighthouse handler", nil, err)
	}

	var messageMetrics *MessageMetrics
	if c.GetBool("stats.message_metrics", false) {
		messageMetrics = newMessageMetrics()
	} else {
		messageMetrics = newMessageMetricsOnlyRecvError()
	}

	useRelays := c.GetBool("relay.use_relays", DefaultUseRelays) && !c.GetBool("relay.am_relay", false)

	handshakeConfig := HandshakeConfig{
		tryInterval:   c.GetDuration("handshakes.try_interval", DefaultHandshakeTryInterval),
		retries:       c.GetInt("handshakes.retries", DefaultHandshakeRetries),
		triggerBuffer: c.GetInt("handshakes.trigger_buffer", DefaultHandshakeTriggerBuffer),
		useRelays:     useRelays,

		messageMetrics: messageMetrics,
	}

	handshakeManager := NewHandshakeManager(l, tunCidr, preferredRanges, hostMap, lightHouse, udpConns[0], handshakeConfig)
	lightHouse.handshakeTrigger = handshakeManager.trigger

	serveDns := false
	if c.GetBool("lighthouse.serve_dns", false) {
		if c.GetBool("lighthouse.am_lighthouse", false) {
			serveDns = true
		} else {
			l.Warn("DNS server refusing to run because this host is not a lighthouse.")
		}
	}

	checkInterval := c.GetInt("timers.connection_alive_interval", 5)
	pendingDeletionInterval := c.GetInt("timers.pending_deletion_interval", 10)

	ifConfig := &InterfaceConfig{
		HostMap:                 hostMap,
		Inside:                  tun,
		Outside:                 udpConns[0],
		certState:               cs,
		Cipher:                  c.GetString("cipher", "aes"),
		Firewall:                fw,
		ServeDns:                serveDns,
		HandshakeManager:        handshakeManager,
		lightHouse:              lightHouse,
		checkInterval:           time.Second * time.Duration(checkInterval),
		pendingDeletionInterval: time.Second * time.Duration(pendingDeletionInterval),
		tryPromoteEvery:         c.GetUint32("counters.try_promote", defaultPromoteEvery),
		reQueryEvery:            c.GetUint32("counters.requery_every_packets", defaultReQueryEvery),
		reQueryWait:             c.GetDuration("timers.requery_wait_duration", defaultReQueryWait),
		DropLocalBroadcast:      c.GetBool("tun.drop_local_broadcast", false),
		DropMulticast:           c.GetBool("tun.drop_multicast", false),
		routines:                routines,
		MessageMetrics:          messageMetrics,
		version:                 buildVersion,
		caPool:                  caPool,
		disconnectInvalid:       c.GetBool("pki.disconnect_invalid", false),
		relayManager:            NewRelayManager(ctx, l, hostMap, c),
		punchy:                  punchy,

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
		ifce, err = NewInterface(ctx, ifConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize interface: %s", err)
		}

		// TODO: Better way to attach these, probably want a new interface in InterfaceConfig
		// I don't want to make this initial commit too far-reaching though
		ifce.writers = udpConns
		lightHouse.ifce = ifce

		ifce.RegisterConfigChangeCallbacks(c)
		ifce.reloadSendRecvError(c)

		go handshakeManager.Run(ctx, ifce)
	}

	// TODO - stats third-party modules start uncancellable goroutines. Update those libs to accept
	// a context so that they can exit when the context is Done.
	statsStart, err := startStats(l, c, buildVersion, configTest)

	if err != nil {
		return nil, util.NewContextualError("Failed to start stats emitter", nil, err)
	}

	if configTest {
		return nil, nil
	}

	//TODO: check if we _should_ be emitting stats
	go ifce.emitStats(ctx, c.GetDuration("stats.interval", time.Second*10))

	attachCommands(l, c, ssh, ifce)

	// Start DNS server last to allow using the nebula IP as lighthouse.dns.host
	var dnsStart func()
	if lightHouse.amLighthouse && serveDns {
		l.Debugln("Starting dns server")
		dnsStart = dnsMain(l, hostMap, c)
	}

	return &Control{
		ifce,
		l,
		cancel,
		sshStart,
		statsStart,
		dnsStart,
		lightHouse.StartUpdateWorker,
	}, nil
}
