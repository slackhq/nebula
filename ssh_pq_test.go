package nebula

import "testing"

func TestPQBindingVerdict(t *testing.T) {
	cases := []struct{ cert, hint, want string }{
		{"aa", "aa", "ok"},
		{"aa", "bb", "mismatch"},
		{"aa", "", "cert-only"},
		{"", "bb", "hint-only"},
		{"", "", "none"},
	}
	for _, c := range cases {
		if got := pqBindingVerdict(c.cert, c.hint); got != c.want {
			t.Fatalf("(%q,%q) = %q, want %q", c.cert, c.hint, got, c.want)
		}
	}
}
