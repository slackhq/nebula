package port_forwarder

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
	"golang.org/x/sync/errgroup"
)

type ForwardConfigOutgoingTcp struct {
	ForwardConfigOutgoing
}

func (cfg ForwardConfigOutgoingTcp) ConfigDescriptor() string {
	return fmt.Sprintf("outbound.tcp.%s.%s", cfg.localListen, cfg.remoteConnect)
}

type ForwardConfigIncomingTcp struct {
	ForwardConfigIncoming
}

func (cfg ForwardConfigIncomingTcp) ConfigDescriptor() string {
	return fmt.Sprintf("inbound.tcp.%d.%s", cfg.port, cfg.forwardLocalAddress)
}

type PortForwardingCommonTcp struct {
	ctx                   context.Context
	wg                    *sync.WaitGroup
	l                     *logrus.Logger
	tunService            *service.Service
	localListenConnection net.Listener
}

func (fwd PortForwardingCommonTcp) Close() error {
	fwd.localListenConnection.Close()
	fwd.wg.Wait()
	return nil
}

type PortForwardingOutgoingTcp struct {
	PortForwardingCommonTcp
	cfg ForwardConfigOutgoingTcp
}

func (cf ForwardConfigOutgoingTcp) SetupPortForwarding(
	tunService *service.Service,
	l *logrus.Logger,
) (io.Closer, error) {
	localTcpListenAddr, err := net.ResolveTCPAddr("tcp", cf.localListen)
	if err != nil {
		return nil, err
	}
	localListenPort, err := net.ListenTCP("tcp", localTcpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Infof("TCP port forwarding to '%v': listening on local TCP addr: '%v'",
		cf.remoteConnect, localTcpListenAddr)

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	portForwarding := &PortForwardingOutgoingTcp{
		PortForwardingCommonTcp: PortForwardingCommonTcp{
			ctx:                   ctx,
			wg:                    wg,
			l:                     l,
			tunService:            tunService,
			localListenConnection: localListenPort,
		},
		cfg: cf,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		portForwarding.acceptOnLocalListenPort_generic(portForwarding.handleClientConnectionWithErrorReturn)
	}()

	return portForwarding, nil
}

func (pt *PortForwardingCommonTcp) acceptOnLocalListenPort_generic(
	handleClientConnectionWithErrorReturn func(localConnection net.Conn) error,
) error {
	for {
		pt.l.Debug("listening on local TCP port ...")
		connection, err := pt.localListenConnection.Accept()
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("accept TCP connect from local TCP port: %v", connection.RemoteAddr())

		pt.wg.Add(1)
		go func() {
			defer pt.wg.Done()
			defer connection.Close()
			<-pt.ctx.Done()
		}()

		pt.wg.Add(1)
		go func() {
			defer pt.wg.Done()
			err := handleClientConnectionWithErrorReturn(connection)
			if err != nil {
				pt.l.Debugf("Closed TCP client connection %s. Err: %+v",
					connection.LocalAddr().String(), err)
			}
		}()
	}
}

func (pt *PortForwardingOutgoingTcp) handleClientConnectionWithErrorReturn(localConnection net.Conn) error {

	remoteConnection, err := pt.tunService.DialContext(context.Background(), "tcp", pt.cfg.remoteConnect)
	if err != nil {
		return err
	}
	return handleTcpClientConnectionPair_generic(pt.l, localConnection, remoteConnection)
}

func handleTcpClientConnectionPair_generic(l *logrus.Logger, connA, connB net.Conn) error {

	dataTransferHandler := func(from, to net.Conn) error {

		name := fmt.Sprintf("%s -> %s", from.LocalAddr().String(), to.LocalAddr().String())

		defer from.Close()
		defer to.Close()

		// no write/read timeout
		to.SetDeadline(time.Time{})
		from.SetDeadline(time.Time{})
		megabyte := (1 << 20)
		buf := make([]byte, 1*megabyte)
		if false {
			// this variant seems to be slightly slower on the local speed-test. 1.60GiB/s vs. 1.70GiB/s
			n, err := io.CopyBuffer(to, from, buf)
			l.WithError(err).
				WithField("payloadSize", n).
				WithField("from", from.RemoteAddr()).
				WithField("to", to.RemoteAddr()).
				WithField("localFrom", from.LocalAddr()).
				WithField("localTo", to.LocalAddr()).
				Debug("stopped data forwarding")
			return err
		} else {
			for {
				rn, r_err := from.Read(buf)
				l.Tracef("%s read(%d), err: %v", name, rn, r_err)
				for i := 0; i < rn; {
					wn, w_err := to.Write(buf[i:rn])
					if w_err != nil {
						l.Debugf("%s writing(%d) to to-connection failed: %v", name, rn, w_err)
						return w_err
					}
					i += wn
				}
				if r_err != nil {
					l.Debugf("%s reading(%d) from from-connection failed: %v", name, rn, r_err)
					return r_err
				}
			}
		}
	}

	errGroup := errgroup.Group{}

	errGroup.Go(func() error { return dataTransferHandler(connA, connB) })
	errGroup.Go(func() error { return dataTransferHandler(connB, connA) })

	return errGroup.Wait()
}

type PortForwardingIncomingTcp struct {
	PortForwardingCommonTcp
	cfg ForwardConfigIncomingTcp
}

func (cf ForwardConfigIncomingTcp) SetupPortForwarding(
	tunService *service.Service,
	l *logrus.Logger,
) (io.Closer, error) {

	localListenPort, err := tunService.Listen("tcp", fmt.Sprintf(":%d", cf.port))
	if err != nil {
		return nil, err
	}

	l.Infof("TCP port forwarding to '%v': listening on local, outside TCP addr: ':%d'",
		cf.forwardLocalAddress, cf.port)

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	portForwarding := &PortForwardingIncomingTcp{
		PortForwardingCommonTcp: PortForwardingCommonTcp{
			ctx:                   ctx,
			wg:                    wg,
			l:                     l,
			tunService:            tunService,
			localListenConnection: localListenPort,
		},
		cfg: cf,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		portForwarding.acceptOnLocalListenPort_generic(portForwarding.handleClientConnectionWithErrorReturn)
	}()

	return portForwarding, nil
}

func (pt *PortForwardingIncomingTcp) handleClientConnectionWithErrorReturn(outsideConnection net.Conn) error {

	fwdAddr, err := net.ResolveTCPAddr("tcp", pt.cfg.forwardLocalAddress)
	if err != nil {
		return err
	}

	localConnection, err := net.DialTCP("tcp", nil, fwdAddr)
	if err != nil {
		return err
	}

	return handleTcpClientConnectionPair_generic(pt.l, outsideConnection, localConnection)
}
