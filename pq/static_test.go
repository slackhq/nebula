package pq

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStaticProviderFromFile(t *testing.T) {
	dir := t.TempDir()
	psk := bytes.Repeat([]byte{0x42}, 32)
	path := filepath.Join(dir, "mesh.psk")
	if err := os.WriteFile(path, psk, 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := NewStaticProviderFromFile(path)
	if err != nil {
		t.Fatalf("valid 32-byte file refused: %v", err)
	}
	defer p.Close()

	got := p.Lookup(nil)
	if !bytes.Equal(got, psk) {
		t.Fatalf("Lookup returned %x, want %x", got, psk)
	}
	// Returned bytes must be caller-owned: mutating them must not poison
	// later lookups.
	got[0] ^= 0xFF
	if again := p.Lookup(nil); !bytes.Equal(again, psk) {
		t.Fatal("Lookup result aliases the provider's internal PSK")
	}
}

func TestStaticProviderFromFileRejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	// 33 bytes — the classic trailing-newline mistake.
	path := filepath.Join(dir, "mesh.psk")
	if err := os.WriteFile(path, append(bytes.Repeat([]byte{0x42}, 32), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStaticProviderFromFile(path); err == nil {
		t.Fatal("33-byte file accepted; want exact-32 rejection")
	}
}

func TestStaticProviderFromFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.psk")
	if err := os.WriteFile(target, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.psk")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStaticProviderFromFile(link); err == nil {
		t.Fatal("symlinked PSK path accepted; O_NOFOLLOW must refuse it")
	}
}
