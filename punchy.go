package nebula

import (
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

type Punchy struct {
	punch           atomic.Bool
	respond         atomic.Bool
	delay           atomic.Int64
	respondDelay    atomic.Int64
	punchEverything atomic.Bool
	l               *logrus.Logger
}

func NewPunchyFromConfig(l *logrus.Logger, c *config.C) *Punchy {
	p := &Punchy{l: l}

	p.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		p.reload(c, false)
	})

	return p
}

func (p *Punchy) reload(c *config.C, initial bool) {
	if initial {
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

	} else if c.HasChanged("punchy.punch") || c.HasChanged("punchy") {
		//TODO: it should be relatively easy to support this, just need to be able to cancel the goroutine and boot it up from here
		p.l.Warn("Changing punchy.punch with reload is not supported, ignoring.")
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

	if initial || c.HasChanged("punchy.target_all_remotes") {
		p.punchEverything.Store(c.GetBool("punchy.target_all_remotes", false))
		if !initial {
			p.l.WithField("target_all_remotes", p.GetTargetEverything()).Info("punchy.target_all_remotes changed")
		}
	}

	if initial || c.HasChanged("punchy.respond_delay") {
		p.respondDelay.Store((int64)(c.GetDuration("punchy.respond_delay", 5*time.Second)))
		if !initial {
			p.l.Infof("punchy.respond_delay changed to %s", p.GetRespondDelay())
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

func (p *Punchy) GetRespondDelay() time.Duration {
	return (time.Duration)(p.respondDelay.Load())
}

func (p *Punchy) GetTargetEverything() bool {
	return p.punchEverything.Load()
}
