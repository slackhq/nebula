package nebula

import (
	"errors"
	"fmt"
	"github.com/imdario/mergo"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	path        string
	files       []string
	Settings    map[interface{}]interface{}
	oldSettings map[interface{}]interface{}
	callbacks   []func(*Config)
}

func NewConfig() *Config {
	return &Config{
		Settings: make(map[interface{}]interface{}),
	}
}

// Load will find all yaml files within path and load them in lexical order
func (c *Config) Load(path string) error {
	c.path = path
	c.files = make([]string, 0)

	err := c.resolve(path)
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

func (c *Config) LoadString(raw string) error {
	if raw == "" {
		return errors.New("Empty configuration")
	}
	return c.parseRaw([]byte(raw))
}

// RegisterReloadCallback stores a function to be called when a config reload is triggered. The functions registered
// here should decide if they need to make a change to the current process before making the change. HasChanged can be
// used to help decide if a change is necessary.
// These functions should return quickly or spawn their own go routine if they will take a while
func (c *Config) RegisterReloadCallback(f func(*Config)) {
	c.callbacks = append(c.callbacks, f)
}

// HasChanged checks if the underlying structure of the provided key has changed after a config reload. The value of
// k in both the old and new settings will be serialized, the result of the string comparison is returned.
// If k is an empty string the entire config is tested.
// It's important to note that this is very rudimentary and susceptible to configuration ordering issues indicating
// there is change when there actually wasn't any.
func (c *Config) HasChanged(k string) bool {
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
		l.WithField("config_path", k).WithError(err).Error("Error while marshaling new config")
	}

	oldVals, err := yaml.Marshal(ov)
	if err != nil {
		l.WithField("config_path", k).WithError(err).Error("Error while marshaling old config")
	}

	return string(newVals) != string(oldVals)
}

// CatchHUP will listen for the HUP signal in a go routine and reload all configs found in the
// original path provided to Load. The old settings are shallow copied for change detection after the reload.
func (c *Config) CatchHUP() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	go func() {
		for range ch {
			l.Info("Caught HUP, reloading config")
			c.ReloadConfig()
		}
	}()
}

func (c *Config) ReloadConfig() {
	c.oldSettings = make(map[interface{}]interface{})
	for k, v := range c.Settings {
		c.oldSettings[k] = v
	}

	err := c.Load(c.path)
	if err != nil {
		l.WithField("config_path", c.path).WithError(err).Error("Error occurred while reloading config")
		return
	}

	for _, v := range c.callbacks {
		v(c)
	}
}

// GetString will get the string for k or return the default d if not found or invalid
func (c *Config) GetString(k, d string) string {
	r := c.Get(k)
	if r == nil {
		return d
	}

	return fmt.Sprintf("%v", r)
}

// GetStringSlice will get the slice of strings for k or return the default d if not found or invalid
func (c *Config) GetStringSlice(k string, d []string) []string {
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
func (c *Config) GetMap(k string, d map[interface{}]interface{}) map[interface{}]interface{} {
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
func (c *Config) GetInt(k string, d int) int {
	r := c.GetString(k, strconv.Itoa(d))
	v, err := strconv.Atoi(r)
	if err != nil {
		return d
	}

	return v
}

// GetBool will get the bool for k or return the default d if not found or invalid
func (c *Config) GetBool(k string, d bool) bool {
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
func (c *Config) GetDuration(k string, d time.Duration) time.Duration {
	r := c.GetString(k, "")
	v, err := time.ParseDuration(r)
	if err != nil {
		return d
	}
	return v
}

func (c *Config) Get(k string) interface{} {
	return c.get(k, c.Settings)
}

func (c *Config) get(k string, v interface{}) interface{} {
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

func (c *Config) resolve(path string) error {
	i, err := os.Stat(path)
	if err != nil {
		return nil
	}

	if !i.IsDir() {
		c.addFile(path)
		return nil
	}

	paths, err := readDirNames(path)
	if err != nil {
		return fmt.Errorf("problem while reading directory %s: %s", path, err)
	}

	for _, p := range paths {
		err := c.resolve(filepath.Join(path, p))
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) addFile(path string) error {
	ext := filepath.Ext(path)

	if ext != ".yaml" && ext != ".yml" {
		return nil
	}

	ap, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	c.files = append(c.files, ap)
	return nil
}

func (c *Config) parseRaw(b []byte) error {
	var m map[interface{}]interface{}

	err := yaml.Unmarshal(b, &m)
	if err != nil {
		return err
	}

	c.Settings = m
	return nil
}

func (c *Config) parse() error {
	var m map[interface{}]interface{}

	for _, path := range c.files {
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		var nm map[interface{}]interface{}
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

func configLogger(c *Config) error {
	// set up our logging level
	logLevel, err := logrus.ParseLevel(strings.ToLower(c.GetString("logging.level", "info")))
	if err != nil {
		return fmt.Errorf("%s; possible levels: %s", err, logrus.AllLevels)
	}
	l.SetLevel(logLevel)

	logFormat := strings.ToLower(c.GetString("logging.format", "text"))
	switch logFormat {
	case "text":
		l.Formatter = &logrus.TextFormatter{}
	case "json":
		l.Formatter = &logrus.JSONFormatter{}
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", logFormat, []string{"text", "json"})
	}

	return nil
}
