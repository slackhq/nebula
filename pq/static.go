package pq

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// StaticProvider serves a single mesh-wide 32-byte PSK regardless of
// peer identity. Maps to the legacy pq_psk_path config knob. Lookups
// always return the same bytes; Subscribe fires only when the
// underlying file is reloaded via NewStaticProviderFromFile after an
// external trigger (currently unused — kept symmetric with Provider).
type StaticProvider struct {
	psk       []byte
	sub       chan struct{}
	closeOnce sync.Once
}

// NewStaticProvider returns a Provider that always serves the given
// 32-byte PSK. Returns an error if psk is not exactly 32 bytes.
func NewStaticProvider(psk []byte) (*StaticProvider, error) {
	if len(psk) != 32 {
		return nil, fmt.Errorf("static psk must be 32 bytes, got %d", len(psk))
	}
	cp := make([]byte, 32)
	copy(cp, psk)
	return &StaticProvider{
		psk: cp,
		sub: make(chan struct{}, 1),
	}, nil
}

// NewStaticProviderFromFile reads exactly 32 bytes from path and
// returns a StaticProvider serving those bytes.
//
// The open refuses symlinks (O_NOFOLLOW) and non-regular files for the
// same reason FileProvider does: a substituted link at a key path must
// not silently redirect the mesh PSK to attacker-chosen bytes.
func NewStaticProviderFromFile(path string) (*StaticProvider, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}
	fd, err := openPSKFileNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer fd.Close()
	fi, err := fd.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("static psk %q is not a regular file", path)
	}
	if fi.Size() != 32 {
		return nil, fmt.Errorf("static psk %q must be exactly 32 bytes, got %d", path, fi.Size())
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(fd, raw); err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return NewStaticProvider(raw)
}

func (s *StaticProvider) Lookup([]byte) []byte {
	// Copy on read: every other Provider implementation does this,
	// and the Provider contract treats returned bytes as caller-
	// owned (matches MemoryProvider/FileProvider semantics). The
	// 32-byte copy cost is negligible against handshake overhead.
	out := make([]byte, len(s.psk))
	copy(out, s.psk)
	return out
}

func (s *StaticProvider) Subscribe() <-chan struct{} {
	return s.sub
}

func (s *StaticProvider) Close() error {
	// sync.Once so a double-close (which can happen when the same
	// provider instance is referenced from both a Compose layer and
	// a direct PKI cleanup path) does not panic with "close of
	// closed channel".
	s.closeOnce.Do(func() { close(s.sub) })
	return nil
}

// LookupRPHash returns "" — a mesh-wide static PSK has no per-peer
// provider-pubkey binding to track. Stub satisfies the Provider
// interface; callers treat "" as "no binding info, defer to policy".
func (s *StaticProvider) LookupRPHash([]byte) string { return "" }

// LookupWithBinding returns the mesh-wide PSK and an always-empty
// rpHash (a static PSK tracks no per-peer binding). ok is true since
// a StaticProvider always serves its single PSK.
func (s *StaticProvider) LookupWithBinding([]byte) (psk []byte, rpHash string, ok bool) {
	return s.Lookup(nil), "", true
}
