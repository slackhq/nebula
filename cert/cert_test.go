package cert

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQuoteName(t *testing.T) {
	assert.Equal(t, `"host"`, QuoteName("host"))
	assert.Equal(t, `"evil\x1b[31m\n"`, QuoteName("evil\x1b[31m\n"))
	assert.Equal(t, `"`+strings.Repeat("a", MaxNameLength)+`"`, QuoteName(strings.Repeat("a", MaxNameLength)))
	assert.Equal(t, `"`+strings.Repeat("a", MaxNameLength)+`"...`, QuoteName(strings.Repeat("a", MaxNameLength+1)))
}
