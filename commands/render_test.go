package commands

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenderPrintsAnOutcomeWithoutText: a command that acts declares no Text. Its
// outcome renders as the reason, the same for every command, and as {ok, reason} in
// JSON, which is the shape these commands have always emitted.
func TestRenderPrintsAnOutcomeWithoutText(t *testing.T) {
	c := &Command{Name: "act"}

	out := &bytes.Buffer{}
	require.NoError(t, Render(c, Did("Closed"), FormatText, out))
	assert.Equal(t, "Closed\n", out.String())

	out.Reset()
	require.NoError(t, Render(c, Failed("No vpn address was provided"), FormatText, out))
	assert.Equal(t, "No vpn address was provided\n", out.String())

	out.Reset()
	require.NoError(t, Render(c, Failed("nope"), FormatJSON, out))
	assert.JSONEq(t, `{"ok":false,"reason":"nope"}`, out.String())
}

// TestRenderHandsTextOnlyTheValue pins the guarantee Result exists for: a command's
// renderer sees the type it returns on success and never the envelope or an outcome, so
// a report command that refuses its arguments needs nothing in its Text to cope.
func TestRenderHandsTextOnlyTheValue(t *testing.T) {
	var got any
	c := &Command{
		Name: "report",
		Text: func(v any, w io.Writer) error {
			got = v
			_, err := io.WriteString(w, "rendered\n")
			return err
		},
	}

	out := &bytes.Buffer{}
	require.NoError(t, Render(c, Value("data"), FormatText, out))
	assert.Equal(t, "data", got)
	assert.Equal(t, "rendered\n", out.String())

	got, out = nil, &bytes.Buffer{}
	require.NoError(t, Render(c, Failed("refused"), FormatText, out))
	assert.Nil(t, got, "Text must not be called for an outcome")
	assert.Equal(t, "refused\n", out.String())

	out.Reset()
	require.NoError(t, Render(c, Value("data"), FormatJSON, out))
	assert.JSONEq(t, `"data"`, out.String(), "JSON carries the value, never the envelope")
}

// TestRenderRefusesTextForAValueWithoutText: leaving Text nil is a statement that no
// human form of the value exists yet, and asking for one is an error that says so.
func TestRenderRefusesTextForAValueWithoutText(t *testing.T) {
	out := &bytes.Buffer{}
	err := Render(&Command{Name: "print-tunnel"}, Value(map[string]int{"index": 7}), FormatText, out)
	require.ErrorIs(t, err, ErrNoTextRendering)
	require.ErrorContains(t, err, "print-tunnel has no human readable output yet")
	assert.Empty(t, out.String())
}

// TestTypedNamesTheTypeOnce: Typed replaces the assertion at the top of every renderer.
// The right type reaches the renderer; the wrong one is reported, naming both.
func TestTypedNamesTheTypeOnce(t *testing.T) {
	type info struct{ Name string }
	render := Typed(func(i info, w io.Writer) error {
		_, err := io.WriteString(w, i.Name+"\n")
		return err
	})

	out := &bytes.Buffer{}
	require.NoError(t, render(info{Name: "tun0"}, out))
	assert.Equal(t, "tun0\n", out.String())

	err := render("not an info", out)
	require.Error(t, err)
	assert.ErrorContains(t, err, "expected commands.info, got string")
}

// TestResultShapes pins what each constructor means to a surface: Empty is the one that
// renders nothing, Payload is what a program receives, and OK is set wherever a reason
// or value says the command worked.
func TestResultShapes(t *testing.T) {
	assert.True(t, Nothing().Empty())
	assert.True(t, Result{}.Empty(), "the zero Result says nothing rather than failing silently")
	assert.False(t, Did("done").Empty())
	assert.False(t, Failed("no").Empty())
	assert.False(t, Value("x").Empty())

	assert.True(t, Value("x").OK)
	assert.True(t, Did("done").OK)
	assert.False(t, Failed("no").OK)

	assert.Equal(t, "x", Value("x").Payload())
	assert.Equal(t, Outcome{OK: true, Reason: "done"}, Did("done").Payload())
	assert.Equal(t, Outcome{Reason: "no"}, Failed("no").Payload())
}
