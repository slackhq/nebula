package localapi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrettyPreservesKeyOrderAndPrecision(t *testing.T) {
	// Keys arrive in the order the daemon wrote them and a uint64 past 2^53 must not be
	// rounded, so the output has to come from re-indenting the bytes rather than from
	// decoding into `any` and encoding again.
	raw := json.RawMessage(`{"z":18446744073709551615,"a":{"y":[1,2],"b":true},"m":"text"}`)

	out, ok := Pretty(raw)
	assert.True(t, ok)
	assert.Equal(t, `{
    "z": 18446744073709551615,
    "a": {
        "y": [
            1,
            2
        ],
        "b": true
    },
    "m": "text"
}`, out)
}

func TestPrettyKeepsAStringValueQuoted(t *testing.T) {
	// A value that is a JSON string is still JSON to whoever asked for it: it has nothing
	// to indent and comes back as it is, never unquoted.
	out, ok := Pretty(json.RawMessage(`"some string"`))
	assert.True(t, ok)
	assert.Equal(t, `"some string"`, out)

	out, ok = Pretty(json.RawMessage(`  "padded"`))
	assert.True(t, ok)
	assert.Equal(t, `"padded"`, out)
}

func TestPrettyRejectsEmptyAndInvalid(t *testing.T) {
	_, ok := Pretty(nil)
	assert.False(t, ok)

	_, ok = Pretty(json.RawMessage("   "))
	assert.False(t, ok)

	_, ok = Pretty(json.RawMessage(`{"a":`))
	assert.False(t, ok)
}
