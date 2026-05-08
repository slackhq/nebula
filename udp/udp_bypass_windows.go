//go:build (amd64 || arm64) && !e2e_testing
// +build amd64 arm64
// +build !e2e_testing

package udp

import (
	"log/slog"
	"sync"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/wfp"
)

// wrapWithWDFBypass wraps a Conn so that the first ReloadConfig consults listen.windows_bypass_wdf
// and installs a WFP PERMIT filter for the listener's bound UDP port. The session is released when Close runs.
func wrapWithWDFBypass(l *slog.Logger, conn Conn) Conn {
	return &bypassConn{Conn: conn, l: l}
}

type bypassConn struct {
	Conn

	l           *slog.Logger
	installOnce sync.Once
	session     *wfp.Session
}

func (b *bypassConn) ReloadConfig(c *config.C) {
	b.installOnce.Do(func() {
		if !c.GetBool("listen.windows_bypass_wdf", true) {
			return
		}
		addr, err := b.Conn.LocalAddr()
		if err != nil {
			b.l.Warn("Failed to query listener port for WFP bypass", "error", err)
			return
		}
		s, err := wfp.PermitUDPPort(addr.Port())
		if err != nil {
			b.l.Warn("Failed to install WFP bypass filters for listener", "error", err)
			return
		}
		b.l.Info("Installed WFP filters bypassing Windows Defender Firewall on UDP listener port",
			"port", addr.Port())
		b.session = s
	})
	b.Conn.ReloadConfig(c)
}

func (b *bypassConn) Close() error {
	if b.session != nil {
		b.session.Close()
		b.session = nil
	}
	return b.Conn.Close()
}
