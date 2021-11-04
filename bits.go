package nebula

import (
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
)

type Bits struct {
	length             uint64
	current            uint64
	bits               []bool
	firstSeen          bool
	lostCounter        metrics.Counter
	dupeCounter        metrics.Counter
	outOfWindowCounter metrics.Counter
}

func NewBits(bits uint64) *Bits {
	return &Bits{
		length:             bits,
		bits:               make([]bool, bits, bits),
		current:            0,
		lostCounter:        metrics.GetOrRegisterCounter("network.packets.lost", nil),
		dupeCounter:        metrics.GetOrRegisterCounter("network.packets.duplicate", nil),
		outOfWindowCounter: metrics.GetOrRegisterCounter("network.packets.out_of_window", nil),
	}
}

func (b *Bits) Check(l logrus.FieldLogger, i uint64) bool {
	// If i is the next number, return true.
	if i > b.current || (i == 0 && b.firstSeen == false && b.current < b.length) {
		return true
	}

	// If i is within the window, check if it's been set already. The first window will fail this check
	if i > b.current-b.length {
		return !b.bits[i%b.length]
	}

	// If i is within the first window
	if i < b.length {
		return !b.bits[i%b.length]
	}

	// Not within the window
	l.Debugf("rejected a packet (top) %d %d\n", b.current, i)
	return false
}

func (b *Bits) Update(l *logrus.Logger, i uint64) bool {
	// If i is the next number, return true and update current.
	if i == b.current+1 {
		// Report missed packets, we can only understand what was missed after the first window has been gone through
		if i > b.length && b.bits[i%b.length] == false {
			b.lostCounter.Inc(1)
		}
		b.bits[i%b.length] = true
		b.current = i
		return true
	}

	// If i packet is greater than current but less than the maximum length of our bitmap,
	// flip everything in between to false and move ahead.
	if i > b.current && i < b.current+b.length {
		// In between current and i need to be zero'd to allow those packets to come in later
		for n := b.current + 1; n < i; n++ {
			b.bits[n%b.length] = false
		}

		b.bits[i%b.length] = true
		b.current = i
		//l.Debugf("missed %d packets between %d and %d\n", i-b.current, i, b.current)
		return true
	}

	// If i is greater than the delta between current and the total length of our bitmap,
	// just flip everything in the map and move ahead.
	if i >= b.current+b.length {
		// The current window loss will be accounted for later, only record the jump as loss up until then
		lost := maxInt64(0, int64(i-b.current-b.length))
		//TODO: explain this
		if b.current == 0 {
			lost++
		}

		for n := range b.bits {
			// Don't want to count the first window as a loss
			//TODO: this is likely wrong, we are wanting to track only the bit slots that we aren't going to track anymore and this is marking everything as missed
			//if b.bits[n] == false {
			//	lost++
			//}
			b.bits[n] = false
		}

		b.lostCounter.Inc(lost)

		if l.Level >= logrus.DebugLevel {
			l.WithField("receiveWindow", m{"accepted": true, "currentCounter": b.current, "incomingCounter": i, "reason": "window shifting"}).
				Debug("Receive window")
		}
		b.bits[i%b.length] = true
		b.current = i
		return true
	}

	// Allow for the 0 packet to come in within the first window
	if i == 0 && b.firstSeen == false && b.current < b.length {
		b.firstSeen = true
		b.bits[i%b.length] = true
		return true
	}

	// If i is within the window of current minus length (the total pat window size),
	// allow it and flip to true but to NOT change current. We also have to account for the first window
	if ((b.current >= b.length && i > b.current-b.length) || (b.current < b.length && i < b.length)) && i <= b.current {
		if b.current == i {
			if l.Level >= logrus.DebugLevel {
				l.WithField("receiveWindow", m{"accepted": false, "currentCounter": b.current, "incomingCounter": i, "reason": "duplicate"}).
					Debug("Receive window")
			}
			b.dupeCounter.Inc(1)
			return false
		}

		if b.bits[i%b.length] == true {
			if l.Level >= logrus.DebugLevel {
				l.WithField("receiveWindow", m{"accepted": false, "currentCounter": b.current, "incomingCounter": i, "reason": "old duplicate"}).
					Debug("Receive window")
			}
			b.dupeCounter.Inc(1)
			return false
		}

		b.bits[i%b.length] = true
		return true

	}

	// In all other cases, fail and don't change current.
	b.outOfWindowCounter.Inc(1)
	if l.Level >= logrus.DebugLevel {
		l.WithField("accepted", false).
			WithField("currentCounter", b.current).
			WithField("incomingCounter", i).
			WithField("reason", "nonsense").
			Debug("Receive window")
	}
	return false
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}

	return b
}
