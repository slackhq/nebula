package nebula

import (
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

type Punchy struct {
	atomicPunch        int32
	atomicRespond      int32
	atomicDelay        time.Duration
	atomicRespondDelay time.Duration
	l                  *logrus.Logger
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

		if yes {
			atomic.StoreInt32(&p.atomicPunch, 1)
		} else {
			atomic.StoreInt32(&p.atomicPunch, 0)
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

		if yes {
			atomic.StoreInt32(&p.atomicRespond, 1)
		} else {
			atomic.StoreInt32(&p.atomicRespond, 0)
		}

		if !initial {
			p.l.Infof("punchy.respond changed to %v", p.GetRespond())
		}
	}

	//NOTE: this will not apply to any in progress operations, only the next one
	if initial || c.HasChanged("punchy.delay") {
		atomic.StoreInt64((*int64)(&p.atomicDelay), (int64)(c.GetDuration("punchy.delay", time.Second)))
		if !initial {
			p.l.Infof("punchy.delay changed to %s", p.GetDelay())
		}
	}
	if initial || c.HasChanged("punchy.respond_delay") {
		atomic.StoreInt64((*int64)(&p.atomicRespondDelay), (int64)(c.GetDuration("punchy.respond_delay", 5*time.Second)))
		if !initial {
			p.l.Infof("punchy.respond_delay changed to %s", p.GetRespondDelay())
		}
	}
}

func (p *Punchy) GetPunch() bool {
	return atomic.LoadInt32(&p.atomicPunch) == 1
}

func (p *Punchy) GetRespond() bool {
	return atomic.LoadInt32(&p.atomicRespond) == 1
}

func (p *Punchy) GetDelay() time.Duration {
	return (time.Duration)(atomic.LoadInt64((*int64)(&p.atomicDelay)))
}

func (p *Punchy) GetRespondDelay() time.Duration {
	return (time.Duration)(atomic.LoadInt64((*int64)(&p.atomicRespondDelay)))
}
