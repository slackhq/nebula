package port_forwarder

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type ForwardConfigOutgoingUdp struct {
	ForwardConfigOutgoing
}

func (cfg ForwardConfigOutgoingUdp) ConfigDescriptor() string {
	return fmt.Sprintf("outbound.udp.%s.%s", cfg.localListen, cfg.remoteConnect)
}

type ForwardConfigIncomingUdp struct {
	ForwardConfigIncoming
}

func (cfg ForwardConfigIncomingUdp) ConfigDescriptor() string {
	return fmt.Sprintf("inbound.udp.%d.%s", cfg.port, cfg.forwardLocalAddress)
}

// use UDP timeout of 300 seconds according to
// https://support.goto.com/connect/help/what-are-the-recommended-nat-keep-alive-settings
var UDP_CONNECTION_TIMEOUT_SECONDS uint32 = 300

type udpConnInterface interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
}

func handleUdpDestinationPortResponseReading[destConn net.Conn, srcConn udpConnInterface](
	l *logrus.Logger,
	loggingFields logrus.Fields,
	closedConnections *chan string,
	sourceAddr net.Addr,
	destConnection *TimedConnection[destConn],
	localListenConnection srcConn,
) error {
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for remoteConnection to protect by mutex

	defer func() { (*closedConnections) <- sourceAddr.String() }()

	l.WithFields(loggingFields).Debug("begin reading responses ...")
	buf := make([]byte, 2*(1<<16))
	for {
		destConnection.connection.SetDeadline(time.Now().Add(time.Second * 10))
		l.WithFields(loggingFields).Trace("response read ...")
		n, err := destConnection.connection.Read(buf)
		if n == 0 {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				l.WithFields(loggingFields).Debug("response read - timeout tick")
				if destConnection.timeout_counter.Increment(10) {
					l.WithFields(loggingFields).Debug("response read - closed due to timeout")
					return nil
				}
				continue
			} else {
				l.WithFields(loggingFields).WithError(err).Debugf("response read - close due to error")
				return err
			}
		}

		destConnection.timeout_counter.Reset()
		l.WithFields(loggingFields).
			WithField("payloadSize", n).
			Debug("response forward")
		n, err = localListenConnection.WriteTo(buf[:n], sourceAddr)
		if n == 0 && (err != nil) {
			l.WithFields(loggingFields).WithError(err).Debugf("response forward - write error")
			return err
		}
	}
}

func handleClosedConnections[C any](
	l *logrus.Logger,
	closedConnections *chan string,
	portReaders *map[string]bool,
	remoteConnections *map[string]*TimedConnection[C],
) {
cleanup:
	for {
		select {
		case closedOne := <-(*closedConnections):
			l.Debugf("closing connection to %s", closedOne)
			delete(*remoteConnections, closedOne)
			delete(*portReaders, closedOne)
		default:
			break cleanup
		}
	}
}

type PortForwardingOutgoingUdp struct {
	l          *logrus.Logger
	tunService *service.Service
	cfg        ForwardConfigOutgoingUdp
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for localListenConnection to protect by mutex
	localListenConnection *net.UDPConn
}

func (fwd PortForwardingOutgoingUdp) Close() error {
	fwd.localListenConnection.Close()
	return nil
}

func (cfg ForwardConfigOutgoingUdp) SetupPortForwarding(
	tunService *service.Service,
	l *logrus.Logger,
) (io.Closer, error) {
	localUdpListenAddr, err := net.ResolveUDPAddr("udp", cfg.localListen)
	if err != nil {
		return nil, err
	}
	remoteUdpAddr, err := net.ResolveUDPAddr("udp", cfg.remoteConnect)
	if err != nil {
		return nil, err
	}

	localListenConnection, err := net.ListenUDP("udp", localUdpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port forwarding to '%v': listening on local UDP addr: '%v'",
		remoteUdpAddr, localUdpListenAddr)

	portForwarding := &PortForwardingOutgoingUdp{
		l:                     l,
		tunService:            tunService,
		cfg:                   cfg,
		localListenConnection: localListenConnection,
	}

	go portForwarding.listenLocalPort()

	return portForwarding, nil
}

func (pt *PortForwardingOutgoingUdp) listenLocalPort() error {
	outsideReaderGroup := errgroup.Group{}
	outsidePortReaders := make(map[string]bool)
	remoteConnections := make(map[string]*TimedConnection[*gonet.UDPConn])
	closedConnections := make(chan string)

	loggingFields := logrus.Fields{
		"a":      "UDP fwd out",
		"listen": pt.localListenConnection.LocalAddr(),
		"dial":   pt.cfg.remoteConnect,
	}

	pt.l.WithFields(loggingFields).Debug("start listening ...")
	var buf [512 * 1024]byte
	for {
		handleClosedConnections(pt.l, &closedConnections, &outsidePortReaders, &remoteConnections)

		pt.l.WithFields(loggingFields).Trace("reading data ...")
		n, localSourceAddr, err := pt.localListenConnection.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.WithFields(loggingFields).
			WithField("source", localSourceAddr).
			WithField("payloadSize", n).
			Trace("read data")

		remoteConnection, ok := remoteConnections[localSourceAddr.String()]
		if !ok {
			newRemoteConn, err := pt.tunService.DialUDP(pt.cfg.remoteConnect)
			if err != nil {
				return err
			}
			remoteConnection = &TimedConnection[*gonet.UDPConn]{
				connection:      newRemoteConn,
				timeout_counter: NewTimeoutCounter(UDP_CONNECTION_TIMEOUT_SECONDS),
			}
			remoteConnections[localSourceAddr.String()] = remoteConnection
		}

		pt.l.WithFields(loggingFields).
			WithField("source", localSourceAddr).
			WithField("dialSource", remoteConnection.connection.LocalAddr()).
			WithField("payloadSize", n).
			Debug("forward")

		remoteConnection.timeout_counter.Reset()
		remoteConnection.connection.Write(buf[:n])

		_, ok = outsidePortReaders[localSourceAddr.String()]
		if !ok {
			loggingFieldsRsp := logrus.Fields{
				"source":     localSourceAddr,
				"dialSource": remoteConnection.connection.LocalAddr(),
			}
			for k, v := range loggingFields {
				loggingFieldsRsp[k] = v
			}
			outsidePortReaders[localSourceAddr.String()] = true
			outsideReaderGroup.Go(func() error {
				return handleUdpDestinationPortResponseReading(
					pt.l, loggingFieldsRsp, &closedConnections, localSourceAddr,
					remoteConnection, pt.localListenConnection)
			})
		}
	}
}

type PortForwardingIncomingUdp struct {
	l                       *logrus.Logger
	tunService              *service.Service
	cfg                     ForwardConfigIncomingUdp
	outsideListenConnection *gonet.UDPConn
}

func (fwd PortForwardingIncomingUdp) Close() error {
	fwd.outsideListenConnection.Close()
	return nil
}

func (cfg ForwardConfigIncomingUdp) SetupPortForwarding(
	tunService *service.Service,
	l *logrus.Logger,
) (io.Closer, error) {

	conn, err := tunService.ListenUDP(fmt.Sprintf(":%d", cfg.port))
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port forwarding to '%v': listening on outside UDP addr: ':%d'",
		cfg.forwardLocalAddress, cfg.port)

	forwarding := &PortForwardingIncomingUdp{
		l:                       l,
		tunService:              tunService,
		cfg:                     cfg,
		outsideListenConnection: conn,
	}

	go forwarding.listenLocalOutsidePort()

	return forwarding, nil
}

func (pt *PortForwardingIncomingUdp) listenLocalOutsidePort() error {
	insideReaderGroup := errgroup.Group{}
	insidePortReaders := make(map[string]bool)
	remoteConnections := make(map[string]*TimedConnection[*net.UDPConn])
	closedConnections := make(chan string)
	fwdAddr, err := net.ResolveUDPAddr("udp", pt.cfg.forwardLocalAddress)
	if err != nil {
		return err
	}

	loggingFields := logrus.Fields{
		"a":      "UDP fwd in",
		"listen": pt.outsideListenConnection.LocalAddr(),
		"dial":   pt.cfg.forwardLocalAddress,
	}

	pt.l.WithFields(loggingFields).Debug("start listening")
	var buf [512 * 1024]byte
	for {
		handleClosedConnections(pt.l, &closedConnections, &insidePortReaders, &remoteConnections)

		pt.l.WithFields(loggingFields).Tracef("wait for data ...")
		n, outsideSourceAddr, err := pt.outsideListenConnection.ReadFrom(buf[0:])
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.WithFields(loggingFields).
			WithField("source", outsideSourceAddr).
			WithField("payloadSize", n).
			Trace("received")

		remoteConnection, ok := remoteConnections[outsideSourceAddr.String()]
		if !ok {
			newRemoteConn, err := net.DialUDP("udp", nil, fwdAddr)
			if err != nil {
				return err
			}
			remoteConnection = &TimedConnection[*net.UDPConn]{
				connection:      newRemoteConn,
				timeout_counter: NewTimeoutCounter(UDP_CONNECTION_TIMEOUT_SECONDS),
			}
			remoteConnections[outsideSourceAddr.String()] = remoteConnection
		}

		remoteConnection.connection.Write(buf[:n])
		remoteConnection.timeout_counter.Reset()

		pt.l.WithFields(loggingFields).
			WithField("source", outsideSourceAddr).
			WithField("dialSource", remoteConnection.connection.LocalAddr()).
			WithField("payloadSize", n).
			Debug("forward")

		_, ok = insidePortReaders[outsideSourceAddr.String()]
		if !ok {
			loggingFieldsRsp := logrus.Fields{
				"source":     outsideSourceAddr,
				"dialSource": remoteConnection.connection.LocalAddr(),
			}
			for k, v := range loggingFields {
				loggingFieldsRsp[k] = v
			}
			insidePortReaders[outsideSourceAddr.String()] = true
			insideReaderGroup.Go(func() error {
				return handleUdpDestinationPortResponseReading(
					pt.l, loggingFieldsRsp, &closedConnections, outsideSourceAddr,
					remoteConnection, pt.outsideListenConnection)
			})
		}
	}
}
