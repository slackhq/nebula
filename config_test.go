package nebula

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfig_Load(t *testing.T) {
	dir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err, "ioutil.TempDir")

	// invalid yaml
	c := NewConfig()
	assert.NoError(t, ioutil.WriteFile(filepath.Join(dir, "01.yaml"), []byte(" invalid yaml"), 0644), "ioutil.WriteFile")
	assert.EqualError(t, c.Load(dir), "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `invalid...` into map[interface {}]interface {}")

	// simple multi config merge
	c = NewConfig()
	assert.NoError(t, os.RemoveAll(dir), "os.RemoveAll")
	assert.NoError(t, os.Mkdir(dir, 0755), "os.Mkdir")

	assert.NoError(t, ioutil.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: hi"), 0644), "ioutil.WriteFile")
	assert.NoError(t, ioutil.WriteFile(filepath.Join(dir, "02.yml"), []byte("outer:\n  inner: override\nnew: hi"), 0644), "ioutil.WriteFile")
	assert.NoError(t, c.Load(dir))
	expected := map[interface{}]interface{}{
		"outer": map[interface{}]interface{}{
			"inner": "override",
		},
		"new": "hi",
	}
	assert.Equal(t, expected, c.Settings)

	//TODO: test symlinked file
	//TODO: test symlinked directory
}

func TestConfig_Get(t *testing.T) {
	// test simple type
	c := NewConfig()
	c.Settings["firewall"] = map[interface{}]interface{}{"outbound": "hi"}
	assert.Equal(t, "hi", c.Get("firewall.outbound"))

	// test complex type
	inner := []map[interface{}]interface{}{{"port": "1", "code": "2"}}
	c.Settings["firewall"] = map[interface{}]interface{}{"outbound": inner}
	assert.EqualValues(t, inner, c.Get("firewall.outbound"))

	// test missing
	assert.Nil(t, c.Get("firewall.nope"))
}

func TestConfig_GetStringSlice(t *testing.T) {
	c := NewConfig()
	c.Settings["slice"] = []interface{}{"one", "two"}
	assert.Equal(t, []string{"one", "two"}, c.GetStringSlice("slice", []string{}))
}

func TestConfig_GetBool(t *testing.T) {
	c := NewConfig()
	c.Settings["bool"] = true
	assert.Equal(t, true, c.GetBool("bool", false))

	c.Settings["bool"] = "true"
	assert.Equal(t, true, c.GetBool("bool", false))

	c.Settings["bool"] = false
	assert.Equal(t, false, c.GetBool("bool", true))

	c.Settings["bool"] = "false"
	assert.Equal(t, false, c.GetBool("bool", true))

	c.Settings["bool"] = "Y"
	assert.Equal(t, true, c.GetBool("bool", false))

	c.Settings["bool"] = "yEs"
	assert.Equal(t, true, c.GetBool("bool", false))

	c.Settings["bool"] = "N"
	assert.Equal(t, false, c.GetBool("bool", true))

	c.Settings["bool"] = "nO"
	assert.Equal(t, false, c.GetBool("bool", true))
}

func TestConfig_HasChanged(t *testing.T) {
	// No reload has occurred, return false
	c := NewConfig()
	c.Settings["test"] = "hi"
	assert.False(t, c.HasChanged(""))

	// Test key change
	c = NewConfig()
	c.Settings["test"] = "hi"
	c.oldSettings = map[interface{}]interface{}{"test": "no"}
	assert.True(t, c.HasChanged("test"))
	assert.True(t, c.HasChanged(""))

	// No key change
	c = NewConfig()
	c.Settings["test"] = "hi"
	c.oldSettings = map[interface{}]interface{}{"test": "hi"}
	assert.False(t, c.HasChanged("test"))
	assert.False(t, c.HasChanged(""))
}

func TestConfig_ReloadConfig(t *testing.T) {
	assert := assert.New(t)

	done := make(chan bool, 1)
	dir, err := ioutil.TempDir("", "config-test")
	assert.NoError(err, "ioutil.TempDir")
	assert.NoError(ioutil.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: hi"), 0644), "ioutil.WriteFile")

	c := NewConfig()
	assert.NoError(c.Load(dir), "Config.Load")

	assert.False(c.HasChanged("outer.inner"))
	assert.False(c.HasChanged("outer"))
	assert.False(c.HasChanged(""))

	assert.NoError(ioutil.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: ho"), 0644), "ioutil.WriteFile")

	c.RegisterReloadCallback(func(c *Config) {
		done <- true
	})

	c.ReloadConfig()
	assert.True(c.HasChanged("outer.inner"))
	assert.True(c.HasChanged("outer"))
	assert.True(c.HasChanged(""))

	// Make sure we call the callbacks
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		panic("timeout")
	}

}
