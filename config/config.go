package config

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dario.cat/mergo"
	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"
)

type C struct {
	path        string
	files       []string
	Settings    map[string]any
	oldSettings map[string]any
	callbacks   []func(*C)
	l           *logrus.Logger
	reloadLock  sync.Mutex
}

func NewC(l *logrus.Logger) *C {
	return &C{
		Settings: make(map[string]any),
		l:        l,
	}
}

// Load will find all yaml files within path and load them in lexical order
func (c *C) Load(path string) error {
	c.path = path
	c.files = make([]string, 0)

	err := c.resolve(path, true)
	if err != nil {
		return err
	}

	if len(c.files) == 0 {
		return fmt.Errorf("no config files found at %s", path)
	}

	sort.Strings(c.files)

	err = c.parse()
	if err != nil {
		return err
	}

	return nil
}

func (c *C) LoadString(raw string) error {
	if raw == "" {
		return errors.New("Empty configuration")
	}
	return c.parseRaw([]byte(raw))
}

// RegisterReloadCallback stores a function to be called when a config reload is triggered. The functions registered
// here should decide if they need to make a change to the current process before making the change. HasChanged can be
// used to help decide if a change is necessary.
// These functions should return quickly or spawn their own go routine if they will take a while
func (c *C) RegisterReloadCallback(f func(*C)) {
	c.callbacks = append(c.callbacks, f)
}

// InitialLoad returns true if this is the first load of the config, and ReloadConfig has not been called yet.
func (c *C) InitialLoad() bool {
	return c.oldSettings == nil
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
		nv any
		ov any
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
	if c.path == "" {
		return
	}

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
				c.l.Info("Caught HUP, reloading config")
				c.ReloadConfig()
			}
		}
	}()
}

func (c *C) ReloadConfig() {
	c.reloadLock.Lock()
	defer c.reloadLock.Unlock()

	c.oldSettings = make(map[string]any)
	for k, v := range c.Settings {
		c.oldSettings[k] = v
	}

	err := c.Load(c.path)
	if err != nil {
		c.l.WithField("config_path", c.path).WithError(err).Error("Error occurred while reloading config")
		return
	}

	for _, v := range c.callbacks {
		v(c)
	}
}

func (c *C) ReloadConfigString(raw string) error {
	c.reloadLock.Lock()
	defer c.reloadLock.Unlock()

	c.oldSettings = make(map[string]any)
	for k, v := range c.Settings {
		c.oldSettings[k] = v
	}

	err := c.LoadString(raw)
	if err != nil {
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

	rv, ok := r.([]any)
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
func (c *C) GetMap(k string, d map[string]any) map[string]any {
	r := c.Get(k)
	if r == nil {
		return d
	}

	v, ok := r.(map[string]any)
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

// GetUint32 will get the uint32 for k or return the default d if not found or invalid
func (c *C) GetUint32(k string, d uint32) uint32 {
	r := c.GetInt(k, int(d))
	if r < 0 || uint64(r) > uint64(math.MaxUint32) {
		return d
	}
	return uint32(r)
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

func AsBool(v any) (value bool, ok bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch x {
		case "y", "yes":
			return true, true
		case "n", "no":
			return false, true
		}
	}

	return false, false
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

func (c *C) Get(k string) any {
	return c.get(k, c.Settings)
}

func (c *C) IsSet(k string) bool {
	return c.get(k, c.Settings) != nil
}

func (c *C) get(k string, v any) any {
	parts := strings.Split(k, ".")
	for _, p := range parts {
		m, ok := v.(map[string]any)
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

// direct signifies if this is the config path directly specified by the user,
// versus a file/dir found by recursing into that path
func (c *C) resolve(path string, direct bool) error {
	i, err := os.Stat(path)
	if err != nil {
		return nil
	}

	if !i.IsDir() {
		c.addFile(path, direct)
		return nil
	}

	paths, err := readDirNames(path)
	if err != nil {
		return fmt.Errorf("problem while reading directory %s: %s", path, err)
	}

	for _, p := range paths {
		err := c.resolve(filepath.Join(path, p), false)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *C) addFile(path string, direct bool) error {
	ext := filepath.Ext(path)

	if !direct && ext != ".yaml" && ext != ".yml" {
		return nil
	}

	ap, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	c.files = append(c.files, ap)
	return nil
}

func (c *C) parseRaw(b []byte) error {
	var m map[string]any

	err := yaml.Unmarshal(b, &m)
	if err != nil {
		return err
	}

	c.Settings = m
	return nil
}

func (c *C) parse() error {
	var m map[string]any

	for _, path := range c.files {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var nm map[string]any
		err = yaml.Unmarshal(b, &nm)
		if err != nil {
			return err
		}

		// We need to use WithAppendSlice so that firewall rules in separate
		// files are appended together
		err = mergo.Merge(&nm, m, mergo.WithAppendSlice)
		m = nm
		if err != nil {
			return err
		}
	}

	c.Settings = m
	return nil
}

func readDirNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	paths, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}

	sort.Strings(paths)
	return paths, nil
}
