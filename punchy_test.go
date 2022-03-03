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
	assert.Equal(t, false, p.GetPunch())
	assert.Equal(t, false, p.GetRespond())
	assert.Equal(t, time.Second, p.GetDelay())

	// punchy deprecation
	c.Settings["punchy"] = true
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, true, p.GetPunch())

	// punchy.punch
	c.Settings["punchy"] = map[interface{}]interface{}{"punch": true}
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, true, p.GetPunch())

	// punch_back deprecation
	c.Settings["punch_back"] = true
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, true, p.GetRespond())

	// punchy.respond
	c.Settings["punchy"] = map[interface{}]interface{}{"respond": true}
	c.Settings["punch_back"] = false
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, true, p.GetRespond())

	// punchy.delay
	c.Settings["punchy"] = map[interface{}]interface{}{"delay": "1m"}
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, time.Minute, p.GetDelay())
}

func TestPunchy_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	delay, _ := time.ParseDuration("1m")
	assert.NoError(t, c.LoadString(`
punchy:
  delay: 1m
  respond: false
`))
	p := NewPunchyFromConfig(l, c)
	assert.Equal(t, delay, p.GetDelay())
	assert.Equal(t, false, p.GetRespond())

	newDelay, _ := time.ParseDuration("10m")
	assert.NoError(t, c.ReloadConfigString(`
punchy:
  delay: 10m
  respond: true
`))
	p.reload(c, false)
	assert.Equal(t, newDelay, p.GetDelay())
	assert.Equal(t, true, p.GetRespond())
}
