package nebula

import (
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

type Punchy struct {
	Punch   bool
	Respond bool
	Delay   time.Duration
	l       *logrus.Logger
}

func NewPunchyFromConfig(l *logrus.Logger, c *config.C) *Punchy {
	p := &Punchy{l: l}

	if c.IsSet("punchy.punch") {
		p.Punch = c.GetBool("punchy.punch", false)
	} else {
		// Deprecated fallback
		p.Punch = c.GetBool("punchy", false)
	}

	if c.IsSet("punchy.respond") {
		p.Respond = c.GetBool("punchy.respond", false)
	} else {
		// Deprecated fallback
		p.Respond = c.GetBool("punch_back", false)
	}

	p.Delay = c.GetDuration("punchy.delay", time.Second)
	c.RegisterReloadCallback(p.reload)

	return p
}

func (p *Punchy) reload(c *config.C) {
	np := NewPunchyFromConfig(p.l, c)
	//TODO: it should be relatively easy to support this, just need to be able to cancel the goroutine and boot it up from here
	if np.Punch != p.Punch {
		p.l.Warn("Changing punchy.punch with reload is not supported, ignoring.")
	}

	if p.Respond != np.Respond {
		atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.Respond)), *(*unsafe.Pointer)(unsafe.Pointer(&np.Respond)))
		p.l.Infof("punchy.respond changed to %v", p.Respond)
	}

	//NOTE: this will not apply to any in progress operations, only the next one
	if p.Delay != np.Delay {
		atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.Delay)), *(*unsafe.Pointer)(unsafe.Pointer(&np.Delay)))
		p.l.Infof("punchy.delay changed to %s", p.Delay)
	}
}
