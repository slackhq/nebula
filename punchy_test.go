package nebula

import (
	"testing"
	"time"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPunchyFromConfig(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)

	// Test defaults
	p := NewPunchyFromConfig(l, c)
	assert.False(t, p.GetPunch())
	assert.False(t, p.GetRespond())
	assert.Equal(t, time.Second, p.GetDelay())
	assert.Equal(t, 5*time.Second, p.GetRespondDelay())

	// punchy deprecation
	c.Settings["punchy"] = true
	p = NewPunchyFromConfig(l, c)
	assert.True(t, p.GetPunch())

	// punchy.punch
	c.Settings["punchy"] = map[string]any{"punch": true}
	p = NewPunchyFromConfig(l, c)
	assert.True(t, p.GetPunch())

	// punch_back deprecation
	c.Settings["punch_back"] = true
	p = NewPunchyFromConfig(l, c)
	assert.True(t, p.GetRespond())

	// punchy.respond
	c.Settings["punchy"] = map[string]any{"respond": true}
	c.Settings["punch_back"] = false
	p = NewPunchyFromConfig(l, c)
	assert.True(t, p.GetRespond())

	// punchy.delay
	c.Settings["punchy"] = map[string]any{"delay": "1m"}
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, time.Minute, p.GetDelay())

	// punchy.respond_delay
	c.Settings["punchy"] = map[string]any{"respond_delay": "1m"}
	p = NewPunchyFromConfig(l, c)
	assert.Equal(t, time.Minute, p.GetRespondDelay())
}

func TestPunchy_reload(t *testing.T) {
	l := test.NewLogger()
	c := config.NewC(l)
	delay, _ := time.ParseDuration("1m")
	require.NoError(t, c.LoadString(`
punchy:
  delay: 1m
  respond: false
`))
	p := NewPunchyFromConfig(l, c)
	assert.Equal(t, delay, p.GetDelay())
	assert.False(t, p.GetRespond())

	newDelay, _ := time.ParseDuration("10m")
	require.NoError(t, c.ReloadConfigString(`
punchy:
  delay: 10m
  respond: true
`))
	p.reload(c, false)
	assert.Equal(t, newDelay, p.GetDelay())
	assert.True(t, p.GetRespond())
}
