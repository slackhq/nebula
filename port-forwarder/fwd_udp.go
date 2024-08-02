package port_forwarder

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
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
	Write(b []byte) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
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

type PortForwardingCommonUdp struct {
	l          *logrus.Logger
	tunService *service.Service
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for localListenConnection to protect by mutex
	localListenConnection io.Closer
}

func (fwd PortForwardingCommonUdp) Close() error {
	fwd.localListenConnection.Close()
	return nil
}

type PortForwardingOutgoingUdp struct {
	PortForwardingCommonUdp
	cfg ForwardConfigOutgoingUdp
}

func (cfg ForwardConfigOutgoingUdp) SetupPortForwarding(
	tunService *service.Service,
	l *logrus.Logger,
) (io.Closer, error) {
	localUdpListenAddr, err := net.ResolveUDPAddr("udp", cfg.localListen)
	if err != nil {
		return nil, err
	}

	localListenConnection, err := net.ListenUDP("udp", localUdpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port forwarding to '%v': listening on local UDP addr: '%v'",
		cfg.remoteConnect, localUdpListenAddr)

	portForwarding := &PortForwardingOutgoingUdp{
		PortForwardingCommonUdp: PortForwardingCommonUdp{
			l:                     l,
			tunService:            tunService,
			localListenConnection: localListenConnection,
		},
		cfg: cfg,
	}

	logPrefix := logrus.Fields{
		"a":      "UDP fwd out",
		"listen": localListenConnection.LocalAddr(),
		"dial":   cfg.remoteConnect,
	}

	go func() {
		err := listenLocalPort_generic(
			l,
			logPrefix,
			localListenConnection,
			func(address string) (*gonet.UDPConn, error) {
				return tunService.DialUDP(address)
			},
			cfg.remoteConnect,
		)
		if err != nil {
			l.WithFields(logPrefix).WithError(err).
				Error("listening stopped with error")
		}
	}()

	return portForwarding, nil
}

func listenLocalPort_generic[destConn net.Conn](
	l *logrus.Logger,
	loggingFields logrus.Fields,
	localListenConnection udpConnInterface,
	dial func(address string) (destConn, error),
	remoteConnect string,
) error {
	dialConnResponseReaders := make(map[string]bool)
	dialConnections := make(map[string]*TimedConnection[destConn])
	closedConnections := make(chan string)

	l.WithFields(loggingFields).Debug("start listening ...")
	var buf [512 * 1024]byte
	for {
		handleClosedConnections(l, &closedConnections, &dialConnResponseReaders, &dialConnections)

		l.WithFields(loggingFields).Trace("reading data ...")
		n, localSourceAddr, err := localListenConnection.ReadFrom(buf[0:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			l.WithFields(loggingFields).Error("listen for data failed. stop.")
			return err
		}

		l.WithFields(loggingFields).
			WithField("source", localSourceAddr).
			WithField("payloadSize", n).
			Trace("read data")

		dialConnection, ok := dialConnections[localSourceAddr.String()]
		if !ok {
			newDialConn, err := dial(remoteConnect)
			if err != nil {
				l.WithFields(loggingFields).WithError(err).Error("dialing dial address failed")
				continue
			}
			dialConnection = &TimedConnection[destConn]{
				connection:      newDialConn,
				timeout_counter: NewTimeoutCounter(UDP_CONNECTION_TIMEOUT_SECONDS),
			}
			dialConnections[localSourceAddr.String()] = dialConnection
		}

		l.WithFields(loggingFields).
			WithField("source", localSourceAddr).
			WithField("dialSource", dialConnection.connection.LocalAddr()).
			WithField("payloadSize", n).
			Debug("forward")

		dialConnection.timeout_counter.Reset()
		dialConnection.connection.Write(buf[:n])

		_, ok = dialConnResponseReaders[localSourceAddr.String()]
		if !ok {
			loggingFieldsRsp := logrus.Fields{
				"source":     localSourceAddr,
				"dialSource": dialConnection.connection.LocalAddr(),
			}
			for k, v := range loggingFields {
				loggingFieldsRsp[k] = v
			}
			dialConnResponseReaders[localSourceAddr.String()] = true
			go func() error {
				return handleUdpDestinationPortResponseReading(
					l, loggingFieldsRsp, &closedConnections, localSourceAddr,
					dialConnection, localListenConnection)
			}()
		}
	}
}

type PortForwardingIncomingUdp struct {
	PortForwardingCommonUdp
	cfg ForwardConfigIncomingUdp
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

	logPrefix := logrus.Fields{
		"a":          "UDP fwd in",
		"listenPort": cfg.port,
		"dial":       cfg.forwardLocalAddress,
	}

	forwarding := &PortForwardingIncomingUdp{
		PortForwardingCommonUdp: PortForwardingCommonUdp{
			l:                     l,
			tunService:            tunService,
			localListenConnection: conn,
		},
		cfg: cfg,
	}

	go func() {
		err := listenLocalPort_generic(
			l,
			logPrefix,
			conn,
			func(address string) (*net.UDPConn, error) {
				fwdAddr, err := net.ResolveUDPAddr("udp", cfg.forwardLocalAddress)
				if err != nil {
					l.WithFields(logPrefix).Error("resolve of dial address failed")
					return nil, err
				}
				return net.DialUDP("udp", nil, fwdAddr)
			},
			cfg.forwardLocalAddress,
		)
		if err != nil {
			l.WithFields(logPrefix).WithError(err).
				Error("listening stopped with error")
		}
	}()

	return forwarding, nil
}
