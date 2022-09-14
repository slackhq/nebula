package nebula

import (
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

type Punchy struct {
	punch     atomic.Bool
	respond   atomic.Bool
	frequency atomic.Int64
	delay     atomic.Int64
	l         *logrus.Logger
	reconfig  chan struct{}
}

func NewPunchyFromConfig(l *logrus.Logger, c *config.C) *Punchy {
	p := &Punchy{l: l, reconfig: make(chan struct{})}

	p.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		p.reload(c, false)
	})

	return p
}

func (p *Punchy) reload(c *config.C, initial bool) {
	// Notify the HostMap Punchy goroutine if punch.punch or punch.frequency is changed.
	// Other punchy values aren't consumed by the HostMap Punchy goroutine.
	punchyUpdated := false
	if initial || c.HasChanged("punchy.punch") {
		punchyUpdated = true
		var yes bool
		if c.IsSet("punchy.punch") {
			yes = c.GetBool("punchy.punch", false)
		} else {
			// Deprecated fallback
			yes = c.GetBool("punchy", false)
		}

		p.punch.Store(yes)
		if yes {
			p.l.Info("punchy enabled")
		} else {
			p.l.Info("punchy disabled")
		}

	}

	if initial || c.HasChanged("punchy.respond") || c.HasChanged("punch_back") {
		var yes bool
		if c.IsSet("punchy.respond") {
			yes = c.GetBool("punchy.respond", false)
		} else {
			// Deprecated fallback
			yes = c.GetBool("punch_back", false)
		}

		p.respond.Store(yes)

		if !initial {
			p.l.Infof("punchy.respond changed to %v", p.GetRespond())
		}
	}

	//NOTE: this will not apply to any in progress operations, only the next one
	if initial || c.HasChanged("punchy.delay") {
		p.delay.Store((int64)(c.GetDuration("punchy.delay", time.Second)))
		if !initial {
			p.l.Infof("punchy.delay changed to %s", p.GetDelay())
		}
	}

	if initial || c.HasChanged("punchy.frequency") {
		punchyUpdated = true
		p.frequency.Store((int64)(c.GetDuration("punchy.frequency", time.Second*10)))
		if !initial {
			p.l.WithField("frequency", p.GetFrequency()).Infof("punchy.frequency changed to %s", p.GetFrequency())
		}
	}

	if punchyUpdated {
		select {
		case p.reconfig <- struct{}{}:
		default:
		}
	}
}

func (p *Punchy) GetPunch() bool {
	return p.punch.Load()
}

func (p *Punchy) GetRespond() bool {
	return p.respond.Load()
}

func (p *Punchy) GetDelay() time.Duration {
	return (time.Duration)(p.delay.Load())
}

func (p *Punchy) GetFrequency() time.Duration {
	return (time.Duration)(p.frequency.Load())
}
