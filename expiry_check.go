package nebula

import (
	"github.com/slackhq/nebula/cert"
	"time"
)

type CertExpiryCheck struct {
	Enabled          bool
	Interface        *Interface
	Ticker           *time.Ticker
	CheckInterval    time.Duration
	TimeLeft         time.Duration
	EndCheckInterval chan bool
}

func NewCertExpiryCheck(c *Config, ifce *Interface) *CertExpiryCheck {
	e := &CertExpiryCheck{
		Enabled:          c.GetBool("pki.expiry_check.enabled", true),
		EndCheckInterval: make(chan bool),
		CheckInterval:    c.GetDuration("pki.expiry_check.log_interval", time.Hour),
		Ticker:           time.NewTicker(c.GetDuration("pki.expiry_check.log_interval", time.Hour)),
		TimeLeft:         c.GetDuration("pki.expiry_check.time_left", 120*time.Hour),
		Interface:        ifce,
	}
	return e
}
func CertTTLInvalid(cert *cert.NebulaCertificate, timeLeft time.Duration) bool {
	return cert.Details.NotAfter.Before(time.Now().Add(timeLeft))
}

func (e *CertExpiryCheck) logExpiryCert() {
	go func() {
		for {
			select {
			case <-e.Ticker.C:
				if CertTTLInvalid(e.Interface.certState.certificate, e.TimeLeft) {
					l.WithField("cert", e.Interface.certState.certificate).Info("nebula certificate is close to expiry")
				}
			case <-e.EndCheckInterval:
				e.Ticker.Stop()
				return
			}
		}
	}()
}

func (e *CertExpiryCheck) RegisterConfigChangeCallbacks(c *Config) {
	c.RegisterReloadCallback(e.reloadConfig)
}

func (e *CertExpiryCheck) reloadConfig(c *Config) {
	oldConfigEnabled := e.Enabled
	e.Enabled = c.GetBool("pki.expiry_check.enabled", true)
	e.CheckInterval = c.GetDuration("pki.expiry_check.log_interval", time.Hour)
	e.TimeLeft = c.GetDuration("pki.expiry_check.time_left", 120*time.Hour)
	e.Ticker = time.NewTicker(e.CheckInterval)
	l.WithField("cert", e.Interface.certState.certificate.Details).Info("reloaded pki.expiry_check configs")
	if e.Enabled && !oldConfigEnabled {
		l.WithField("pki.expiry_cert.enabled", e.Enabled).Info("cert expiry logging is enabled")
		e.EndCheckInterval = make(chan bool)
		e.logExpiryCert()
	}
	if !e.Enabled && oldConfigEnabled {
		l.WithField("pki.expiry_cert.enabled", e.Enabled).Info("cert expiry logging is disabled")
		e.EndCheckInterval <- true
	}
}
