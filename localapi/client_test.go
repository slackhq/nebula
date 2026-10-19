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
	//nolint:testifylint // the layout is what is under test, which JSONEq would not see
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

func TestPrettyLeavesTextAlone(t *testing.T) {
	// A JSON string is a command's plain text output; it is rendered by Text, not indented.
	_, ok := Pretty(json.RawMessage(`"Log level is: info"`))
	assert.False(t, ok)

	_, ok = Pretty(json.RawMessage(`  "padded"`))
	assert.False(t, ok)
}

func TestPrettyRejectsEmptyAndInvalid(t *testing.T) {
	_, ok := Pretty(nil)
	assert.False(t, ok)

	_, ok = Pretty(json.RawMessage("   "))
	assert.False(t, ok)

	_, ok = Pretty(json.RawMessage(`{"a":`))
	assert.False(t, ok)
}
