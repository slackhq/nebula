package nebula

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_sha256KdfFromString(t *testing.T) {
	key := "tooshrt"
	mac, err := sha256KdfFromString(key)
	assert.Nil(t, mac)
	assert.EqualError(t, err, "PSK too short!")

	key = "goodkeyexceptthatitisterriblebecauseitiswordsbutwhatever"
	mac, err = sha256KdfFromString(key)
	assert.Nil(t, err)
	assert.Equal(t, 32, len(mac))
}
