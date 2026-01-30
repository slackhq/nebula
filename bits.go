package nebula

import (
	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
)

type Bits struct {
	length             uint64
	current            uint64
	bits               []bool
	lostCounter        metrics.Counter
	dupeCounter        metrics.Counter
	outOfWindowCounter metrics.Counter
}

func NewBits(bits uint64) *Bits {
	b := &Bits{
		length:             bits,
		bits:               make([]bool, bits, bits),
		current:            0,
		lostCounter:        metrics.GetOrRegisterCounter("network.packets.lost", nil),
		dupeCounter:        metrics.GetOrRegisterCounter("network.packets.duplicate", nil),
		outOfWindowCounter: metrics.GetOrRegisterCounter("network.packets.out_of_window", nil),
	}

	// There is no counter value 0, mark it to avoid counting a lost packet later.
	b.bits[0] = true
	b.current = 0
	return b
}

func (b *Bits) Check(l *logrus.Logger, i uint64) bool {
	// If i is the next number, return true.
	if i > b.current {
		return true
	}

	// If i is within the window, check if it's been set already.
	if i > b.current-b.length || i < b.length && b.current < b.length {
		return !b.bits[i%b.length]
	}

	// Not within the window
	if l.Level >= logrus.DebugLevel {
		l.Debugf("rejected a packet (top) %d %d\n", b.current, i)
	}
	return false
}

func (b *Bits) Update(l *logrus.Logger, i uint64) bool {
	// If i is the next number, return true and update current.
	if i == b.current+1 {
		// Check if the oldest bit was lost since we are shifting the window by 1 and occupying it with this counter
		// The very first window can only be tracked as lost once we are on the 2nd window or greater
		if b.bits[i%b.length] == false && i > b.length {
			b.lostCounter.Inc(1)
		}
		b.bits[i%b.length] = true
		b.current = i
		return true
	}

	// If i is a jump, adjust the window, record lost, update current, and return true
	if i > b.current {
		lost := int64(0)
		// Zero out the bits between the current and the new counter value, limited by the window size,
		// since the window is shifting
		for n := b.current + 1; n <= min(i, b.current+b.length); n++ {
			if b.bits[n%b.length] == false && n > b.length {
				lost++
			}
			b.bits[n%b.length] = false
		}

		// Only record any skipped packets as a result of the window moving further than the window length
		// Any loss within the new window will be accounted for in future calls
		lost += max(0, int64(i-b.current-b.length))
		b.lostCounter.Inc(lost)

		b.bits[i%b.length] = true
		b.current = i
		return true
	}

	// If i is within the current window but below the current counter,
	// Check to see if it's a duplicate
	if i > b.current-b.length || i < b.length && b.current < b.length {
		if b.current == i || b.bits[i%b.length] == true {
			if l.Level >= logrus.DebugLevel {
				l.WithField("receiveWindow", m{"accepted": false, "currentCounter": b.current, "incomingCounter": i, "reason": "duplicate"}).
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
