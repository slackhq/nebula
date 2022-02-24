package nebula

import (
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

func TestNewPunchyFromConfig(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)

	// Test defaults
	p := NewPunchyFromConfig(l, c)
	assert.Equal(t, false, p.Punch)
	assert.Equal(t, false, p.Respond)
	assert.Equal(t, time.Second, p.Delay)

	// punchy deprecation
	c.Settings["punchy"] = true
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, true, p.Punch)

	// punchy.punch
	c.Settings["punchy"] = map[interface{}]interface{}{"punch": true}
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, true, p.Punch)

	// punch_back deprecation
	c.Settings["punch_back"] = true
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, true, p.Respond)

	// punchy.respond
	c.Settings["punchy"] = map[interface{}]interface{}{"respond": true}
	c.Settings["punch_back"] = false
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, true, p.Respond)

	// punchy.delay
	c.Settings["punchy"] = map[interface{}]interface{}{"delay": "1m"}
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, time.Minute, p.Delay)
}

func TestPunchy_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	delay, _ := time.ParseDuration("1m")
	c.Settings["punchy"] = map[interface{}]interface{}{"delay": delay.String(), "respond": false}
	p := NewPunchyFromConfig(l, c)
	assert.Equal(t, delay, p.Delay)
	assert.Equal(t, false, p.Respond)

	newDelay, _ := time.ParseDuration("10m")
	c.Settings["punchy"] = map[interface{}]interface{}{"delay": newDelay.String(), "respond": true}
	p.reload(c)
	assert.Equal(t, newDelay, p.Delay)
	assert.Equal(t, true, p.Respond)

}
