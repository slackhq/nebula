package nebula

import (
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
)

func TestGetListenAddrs(t *testing.T) {
	get := func(t *testing.T, yaml string) []string {
		c := config.NewC(nil)
		if err := c.LoadString(yaml); err != nil {
			t.Fatalf("LoadString: %v", err)
		}
		return getListenAddrs(c, "stats.listen")
	}

	// A single string yields one address.
	assert.Equal(t, []string{"127.0.0.1:8080"},
		get(t, "stats:\n  listen: '127.0.0.1:8080'\n"))

	// A list yields several, in order.
	assert.Equal(t, []string{"100.64.0.5:8080", "[fd00::5]:8080"},
		get(t, "stats:\n  listen:\n    - '100.64.0.5:8080'\n    - '[fd00::5]:8080'\n"))

	// Blank list entries are skipped.
	assert.Equal(t, []string{"127.0.0.1:8080"},
		get(t, "stats:\n  listen:\n    - '127.0.0.1:8080'\n    - ''\n"))

	// Missing and empty values yield nil.
	assert.Nil(t, get(t, "stats:\n  path: /metrics\n"))
	assert.Nil(t, get(t, "stats:\n  listen: ''\n"))
}
