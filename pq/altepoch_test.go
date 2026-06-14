package pq

import (
	"fmt"
	"testing"
	"time"
)

func TestAltEpochHint(t *testing.T) {
	c := NewAltEpochHint()
	now := time.Unix(1000, 0)
	key := "peerhash-a"

	if c.ChoosePrev(key, now) {
		t.Fatal("no history must not suggest previous")
	}

	c.NoteMsg2(key, now, false)
	if !c.ChoosePrev(key, now.Add(10*time.Second)) {
		t.Fatal("rapid re-msg1 after current-epoch msg2 must suggest previous")
	}
	if c.ChoosePrev(key, now.Add(11*time.Second)) {
		t.Fatal("suggestion must fire once per episode")
	}

	// Re-arm: a fresh NoteMsg2 after ChoosePrev consumed the suggestion
	// must reset suggested so the next in-window ChoosePrev fires again.
	t2 := now.Add(20 * time.Second)
	c.NoteMsg2(key, t2, false)
	if !c.ChoosePrev(key, t2.Add(10*time.Second)) {
		t.Fatal("fresh NoteMsg2 after consumed suggestion must re-arm ChoosePrev")
	}

	// Out-of-window no-consume: an out-of-window ChoosePrev must return
	// false without consuming the suggestion, so a subsequent in-window
	// call still fires.
	key2 := "peerhash-b"
	t0 := time.Unix(2000, 0)
	c.NoteMsg2(key2, t0, false)
	if c.ChoosePrev(key2, t0.Add(31*time.Second)) {
		t.Fatal("out-of-window ChoosePrev must return false")
	}
	if !c.ChoosePrev(key2, t0.Add(29*time.Second)) {
		t.Fatal("out-of-window false return must not consume suggestion; in-window call must still fire")
	}

	c.NoteMsg2(key, now, false)
	if c.ChoosePrev(key, now.Add(31*time.Second)) {
		t.Fatal("stale history must not suggest previous")
	}

	c.NoteMsg2(key, now, true)
	if c.ChoosePrev(key, now.Add(5*time.Second)) {
		t.Fatal("after a prev-epoch attempt, fall back to current (no ping-pong)")
	}

	c.NoteMsg2(key, now, false)
	c.Clear(key)
	if c.ChoosePrev(key, now.Add(5*time.Second)) {
		t.Fatal("cleared entry must not suggest previous")
	}
}

func TestAltEpochHintCap(t *testing.T) {
	c := NewAltEpochHint()
	now := time.Unix(1000, 0)
	for i := 0; i < altEpochCap+50; i++ {
		c.NoteMsg2(fmt.Sprintf("key-%d", i), now, false)
	}
	if n := c.len(); n > altEpochCap {
		t.Fatalf("cache grew to %d, cap %d", n, altEpochCap)
	}
}

func TestAltEpochHintExpiry(t *testing.T) {
	c := NewAltEpochHint()
	now := time.Unix(1000, 0)
	c.NoteMsg2("k", now, false)
	if c.ChoosePrev("k", now.Add(altEpochExpiry+time.Second)) {
		t.Fatal("expired entries must not suggest previous")
	}
}
