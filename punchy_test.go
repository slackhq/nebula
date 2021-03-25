package nebula

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewPunchyFromConfig(t *testing.T) {
	l := NewTestLogger()
	c := NewConfig(l)

	// Test defaults
	p := NewPunchyFromConfig(c)
	assert.Equal(t, false, p.Punch)
	assert.Equal(t, false, p.Respond)
	assert.Equal(t, time.Second, p.Delay)

	// punchy deprecation
	c.Settings["punchy"] = true
	p = NewPunchyFromConfig(c)
	assert.Equal(t, true, p.Punch)

	// punchy.punch
	c.Settings["punchy"] = map[interface{}]interface{}{"punch": true}
	p = NewPunchyFromConfig(c)
	assert.Equal(t, true, p.Punch)

	// punch_back deprecation
	c.Settings["punch_back"] = true
	p = NewPunchyFromConfig(c)
	assert.Equal(t, true, p.Respond)

	// punchy.respond
	c.Settings["punchy"] = map[interface{}]interface{}{"respond": true}
	c.Settings["punch_back"] = false
	p = NewPunchyFromConfig(c)
	assert.Equal(t, true, p.Respond)

	// punchy.delay
	c.Settings["punchy"] = map[interface{}]interface{}{"delay": "1m"}
	p = NewPunchyFromConfig(c)
	assert.Equal(t, time.Minute, p.Delay)
}
