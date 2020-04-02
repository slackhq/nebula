package nebula

import "time"

type Punchy struct {
	Punch   bool
	Respond bool
	Delay   time.Duration
}

func NewPunchyFromConfig(c *Config) *Punchy {
	p := &Punchy{}

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
	return p
}
