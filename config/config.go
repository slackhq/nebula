package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/imdario/mergo"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type C struct {
	path        string
	Settings    map[interface{}]interface{}
	oldSettings map[interface{}]interface{}
	callbacks   []func(*C)
	l           *logrus.Logger

	// SIGHUP reload function
	// TODO: is this really necessary, I feel this is a hack
	reloadOnSIGHUP func() error
}

func NewC(l *logrus.Logger) *C {
	return &C{
		Settings: make(map[interface{}]interface{}),
		l:        l,
	}
}

// Load will find all yaml files provided as string slices,
// and load them in the provided order.
// The caller is responsible to provide at least one configuration
// or it will error out.
func (c *C) Load(config ...string) error {
	if len(config) == 0 {
		return errors.New("no configurations provided")
	}

	return c.parse(config...)
}

// RegisterSIGHUPHandler registers a function that gets called when
// SIGHUP gets intercepted.
func (c *C) RegisterSIGHUPHandler(handler func() error) {
	c.reloadOnSIGHUP = handler
}

// RegisterReloadCallback stores a function to be called when a config reload is triggered. The functions registered
// here should decide if they need to make a change to the current process before making the change. HasChanged can be
// used to help decide if a change is necessary.
// These functions should return quickly or spawn their own go routine if they will take a while
func (c *C) RegisterReloadCallback(f func(*C)) {
	c.callbacks = append(c.callbacks, f)
}

// HasChanged checks if the underlying structure of the provided key has changed after a config reload. The value of
// k in both the old and new settings will be serialized, the result of the string comparison is returned.
// If k is an empty string the entire config is tested.
// It's important to note that this is very rudimentary and susceptible to configuration ordering issues indicating
// there is change when there actually wasn't any.
func (c *C) HasChanged(k string) bool {
	if c.oldSettings == nil {
		return false
	}

	var (
		nv interface{}
		ov interface{}
	)

	if k == "" {
		nv = c.Settings
		ov = c.oldSettings
		k = "all settings"
	} else {
		nv = c.get(k, c.Settings)
		ov = c.get(k, c.oldSettings)
	}

	newVals, err := yaml.Marshal(nv)
	if err != nil {
		c.l.WithField("config_path", k).WithError(err).Error("Error while marshaling new config")
	}

	oldVals, err := yaml.Marshal(ov)
	if err != nil {
		c.l.WithField("config_path", k).WithError(err).Error("Error while marshaling old config")
	}

	return string(newVals) != string(oldVals)
}

// CatchHUP will listen for the HUP signal in a go routine and reload all configs found in the
// original path provided to Load. The old settings are shallow copied for change detection after the reload.
func (c *C) CatchHUP(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-ctx.Done():
				signal.Stop(ch)
				close(ch)
				return
			case <-ch:
				c.l.Info("Caught HUP")
				if c.reloadOnSIGHUP != nil {
					if err := c.reloadOnSIGHUP(); err != nil {
						c.l.WithError(err).Error("Error in reloading configs")
						continue
					}
					c.l.Info("succesfully executed SIGHUP handler")
				}
			}
		}
	}()
}

// ReloadConfig tries to reload
func (c *C) ReloadConfig(configs ...string) error {
	if len(configs) == 0 {
		return errors.New("no configurations provided")
	}

	c.oldSettings = make(map[interface{}]interface{})
	for k, v := range c.Settings {
		c.oldSettings[k] = v
	}

	if err := c.Load(configs...); err != nil {
		c.l.WithField("config_path", c.path).WithError(err).Error("Error occurred while reloading config")
		return err
	}

	for _, v := range c.callbacks {
		v(c)
	}

	return nil
}

// GetString will get the string for k or return the default d if not found or invalid
func (c *C) GetString(k, d string) string {
	r := c.Get(k)
	if r == nil {
		return d
	}

	return fmt.Sprintf("%v", r)
}

// GetStringSlice will get the slice of strings for k or return the default d if not found or invalid
func (c *C) GetStringSlice(k string, d []string) []string {
	r := c.Get(k)
	if r == nil {
		return d
	}

	rv, ok := r.([]interface{})
	if !ok {
		return d
	}

	v := make([]string, len(rv))
	for i := 0; i < len(v); i++ {
		v[i] = fmt.Sprintf("%v", rv[i])
	}

	return v
}

// GetMap will get the map for k or return the default d if not found or invalid
func (c *C) GetMap(k string, d map[interface{}]interface{}) map[interface{}]interface{} {
	r := c.Get(k)
	if r == nil {
		return d
	}

	v, ok := r.(map[interface{}]interface{})
	if !ok {
		return d
	}

	return v
}

// GetInt will get the int for k or return the default d if not found or invalid
func (c *C) GetInt(k string, d int) int {
	r := c.GetString(k, strconv.Itoa(d))
	v, err := strconv.Atoi(r)
	if err != nil {
		return d
	}

	return v
}

// GetBool will get the bool for k or return the default d if not found or invalid
func (c *C) GetBool(k string, d bool) bool {
	r := strings.ToLower(c.GetString(k, fmt.Sprintf("%v", d)))
	v, err := strconv.ParseBool(r)
	if err != nil {
		switch r {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
		return d
	}

	return v
}

// GetDuration will get the duration for k or return the default d if not found or invalid
func (c *C) GetDuration(k string, d time.Duration) time.Duration {
	r := c.GetString(k, "")
	v, err := time.ParseDuration(r)
	if err != nil {
		return d
	}
	return v
}

func (c *C) Get(k string) interface{} {
	return c.get(k, c.Settings)
}

func (c *C) IsSet(k string) bool {
	return c.get(k, c.Settings) != nil
}

func (c *C) get(k string, v interface{}) interface{} {
	parts := strings.Split(k, ".")
	for _, p := range parts {
		m, ok := v.(map[interface{}]interface{})
		if !ok {
			return nil
		}

		v, ok = m[p]
		if !ok {
			return nil
		}
	}

	return v
}

// parse reads and merges all the config files provided
func (c *C) parse(configs ...string) error {
	var m map[interface{}]interface{}

	for _, config := range configs {
		var newMap map[interface{}]interface{}

		if err := yaml.Unmarshal([]byte(config), &newMap); err != nil {
			return err
		}

		// We need to use WithAppendSlice so that firewall rules in separate
		// files are appended together
		if err := mergo.Merge(&newMap, m, mergo.WithAppendSlice); err != nil {
			return err
		}

		m = newMap
	}

	c.Settings = m
	return nil
}
