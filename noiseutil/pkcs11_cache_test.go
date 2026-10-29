package noiseutil

import "testing"

func TestGetP11ClientCached(t *testing.T) {
	uri := "pkcs11:token=test1;id=%01;foo;bar"
	c1, finalUri, cache, _ := getP11Client(uri)
	if finalUri != "pkcs11:token=test1;id=%01;foo;bar" {
		t.Fatalf("invalid url %v", finalUri)
	}
	if !cache || c1 == nil {
		t.Fatalf("expected cached non-nil client, got %v %v", c1, cache)
	}

	uri = "pkcs11:token=test1;id=%01;foo;bar?cache-sessions=1"
	c2, finalUri, _, _ := getP11Client(uri)
	if finalUri != "pkcs11:token=test1;id=%01;foo;bar" {
		t.Fatalf("invalid url %v", finalUri)
	}
	if !cache || c2 != c1 {
		t.Fatal("expected same cached client")
	}

	uri = "pkcs11:token=test1;id=%01;foo;bar?cache-sessions"
	c3, finalUri, _, _ := getP11Client(uri)
	if finalUri != "pkcs11:token=test1;id=%01;foo;bar" {
		t.Fatalf("invalid url %v", finalUri)
	}
	if !cache || c3 != c2 {
		t.Fatal("expected same cached client")
	}

	c4, finalUri, cache, _ := getP11Client("pkcs11:token=test1;id=%02?baz=quux&cache-sessions=0")
	if finalUri != "pkcs11:token=test1;id=%02?baz=quux" {
		t.Fatalf("invalid url %v", finalUri)
	}
	if cache || c4 == nil {
		t.Fatalf("expected fresh uncached client, got %v %v", c4, cache)
	}

	c5, finalUri, cache, _ := getP11Client("pkcs11:token=test1;id=%02?baz=quux&cache-sessions=0")
	if finalUri != "pkcs11:token=test1;id=%02?baz=quux" {
		t.Fatalf("invalid url %v", finalUri)
	}
	if cache || c5 == nil || c5 == c4 {
		t.Fatalf("expected fresh uncached client, got %v %v", c5, cache)
	}

	c6, _, cache, err := getP11Client("pkcs11:token=test1;id=%03?foo=bar&cache-sessions=00")
	if c6 != nil || err == nil {
		t.Fatalf("expected parse failure for invalid cache-sessions")
	}
}
