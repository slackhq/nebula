package nebula

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Load(t *testing.T) {
	l := NewTestLogger()
	dir, err := ioutil.TempDir("", "config-test")
	// invalid yaml
	c := NewConfig(l)
	ioutil.WriteFile(filepath.Join(dir, "01.yaml"), []byte(" invalid yaml"), 0644)
	assert.EqualError(t, c.Load(dir), "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `invalid...` into map[interface {}]interface {}")

	// simple multi config merge
	c = NewConfig(l)
	os.RemoveAll(dir)
	os.Mkdir(dir, 0755)

	assert.Nil(t, err)

	ioutil.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: hi"), 0644)
	ioutil.WriteFile(filepath.Join(dir, "02.yml"), []byte("outer:\n  inner: override\nnew: hi"), 0644)
	assert.Nil(t, c.Load(dir))
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
	l := NewTestLogger()
	// test simple type
	c := NewConfig(l)
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
	l := NewTestLogger()
	c := NewConfig(l)
	c.Settings["slice"] = []interface{}{"one", "two"}
	assert.Equal(t, []string{"one", "two"}, c.GetStringSlice("slice", []string{}))
}

func TestConfig_GetBool(t *testing.T) {
	l := NewTestLogger()
	c := NewConfig(l)
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

func TestConfig_GetAllowList(t *testing.T) {
	l := NewTestLogger()
	c := NewConfig(l)
	c.Settings["allowlist"] = map[interface{}]interface{}{
		"192.168.0.0": true,
	}
	r, err := c.GetAllowList("allowlist", false)
	assert.EqualError(t, err, "config `allowlist` has invalid CIDR: 192.168.0.0")
	assert.Nil(t, r)

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"192.168.0.0/16": "abc",
	}
	r, err = c.GetAllowList("allowlist", false)
	assert.EqualError(t, err, "config `allowlist` has invalid value (type string): abc")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"192.168.0.0/16": true,
		"10.0.0.0/8":     false,
	}
	r, err = c.GetAllowList("allowlist", false)
	assert.EqualError(t, err, "config `allowlist` contains both true and false rules, but no default set for 0.0.0.0/0")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"0.0.0.0/0":      true,
		"10.0.0.0/8":     false,
		"10.42.42.0/24":  true,
		"fd00::/8":       true,
		"fd00:fd00::/16": false,
	}
	r, err = c.GetAllowList("allowlist", false)
	assert.EqualError(t, err, "config `allowlist` contains both true and false rules, but no default set for ::/0")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"0.0.0.0/0":     true,
		"10.0.0.0/8":    false,
		"10.42.42.0/24": true,
	}
	r, err = c.GetAllowList("allowlist", false)
	if assert.NoError(t, err) {
		assert.NotNil(t, r)
	}

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"0.0.0.0/0":      true,
		"10.0.0.0/8":     false,
		"10.42.42.0/24":  true,
		"::/0":           false,
		"fd00::/8":       true,
		"fd00:fd00::/16": false,
	}
	r, err = c.GetAllowList("allowlist", false)
	if assert.NoError(t, err) {
		assert.NotNil(t, r)
	}

	// Test interface names

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"interfaces": map[interface{}]interface{}{
			`docker.*`: false,
		},
	}
	r, err = c.GetAllowList("allowlist", false)
	assert.EqualError(t, err, "config `allowlist` does not support `interfaces`")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"interfaces": map[interface{}]interface{}{
			`docker.*`: "foo",
		},
	}
	r, err = c.GetAllowList("allowlist", true)
	assert.EqualError(t, err, "config `allowlist.interfaces` has invalid value (type string): foo")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"interfaces": map[interface{}]interface{}{
			`docker.*`: false,
			`eth.*`:    true,
		},
	}
	r, err = c.GetAllowList("allowlist", true)
	assert.EqualError(t, err, "config `allowlist.interfaces` values must all be the same true/false value")

	c.Settings["allowlist"] = map[interface{}]interface{}{
		"interfaces": map[interface{}]interface{}{
			`docker.*`: false,
		},
	}
	r, err = c.GetAllowList("allowlist", true)
	if assert.NoError(t, err) {
		assert.NotNil(t, r)
	}
}

func TestConfig_HasChanged(t *testing.T) {
	l := NewTestLogger()
	// No reload has occurred, return false
	c := NewConfig(l)
	c.Settings["test"] = "hi"
	assert.False(t, c.HasChanged(""))

	// Test key change
	c = NewConfig(l)
	c.Settings["test"] = "hi"
	c.oldSettings = map[interface{}]interface{}{"test": "no"}
	assert.True(t, c.HasChanged("test"))
	assert.True(t, c.HasChanged(""))

	// No key change
	c = NewConfig(l)
	c.Settings["test"] = "hi"
	c.oldSettings = map[interface{}]interface{}{"test": "hi"}
	assert.False(t, c.HasChanged("test"))
	assert.False(t, c.HasChanged(""))
}

func TestConfig_ReloadConfig(t *testing.T) {
	l := NewTestLogger()
	done := make(chan bool, 1)
	dir, err := ioutil.TempDir("", "config-test")
	assert.Nil(t, err)
	ioutil.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: hi"), 0644)

	c := NewConfig(l)
	assert.Nil(t, c.Load(dir))

	assert.False(t, c.HasChanged("outer.inner"))
	assert.False(t, c.HasChanged("outer"))
	assert.False(t, c.HasChanged(""))

	ioutil.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: ho"), 0644)

	c.RegisterReloadCallback(func(c *Config) {
		done <- true
	})

	c.ReloadConfig()
	assert.True(t, c.HasChanged("outer.inner"))
	assert.True(t, c.HasChanged("outer"))
	assert.True(t, c.HasChanged(""))

	// Make sure we call the callbacks
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		panic("timeout")
	}

}
