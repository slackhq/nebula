package rpidentity

import "testing"

func TestRoundTrip(t *testing.T) {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	blob := Encode(hash, 51820, 51821)

	gotHash, gotRP, gotDisc, ok := Decode(blob)
	if !ok {
		t.Fatal("decode failed on freshly encoded blob")
	}
	if string(gotHash) != string(hash) || gotRP != 51820 || gotDisc != 51821 {
		t.Fatalf("round-trip mismatch: hashEq=%v rp=%d disc=%d", string(gotHash) == string(hash), gotRP, gotDisc)
	}
}

func TestEncodeRejectsBadHash(t *testing.T) {
	if Encode(make([]byte, 31), 1, 2) != nil {
		t.Fatal("Encode must return nil for a non-32-byte hash")
	}
	if Encode(nil, 1, 2) != nil {
		t.Fatal("Encode must return nil for a nil hash")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {}, {0}, {9, 1, 2, 3}, make([]byte, 5), make([]byte, 36)} {
		if _, _, _, ok := Decode(b); ok {
			t.Fatalf("Decode accepted garbage %v", b)
		}
	}
	// wrong version byte
	bad := make([]byte, 37)
	bad[0] = 2
	if _, _, _, ok := Decode(bad); ok {
		t.Fatal("Decode accepted unknown version")
	}
}

func TestCodecRoundTrip(t *testing.T) {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	var c Codec
	blob := c.Encode(hash, 51820, 51821)

	gotHash, gotRP, gotDisc, ok := c.Decode(blob)
	if !ok {
		t.Fatal("Codec.Decode failed on freshly encoded blob")
	}
	if string(gotHash) != string(hash) || gotRP != 51820 || gotDisc != 51821 {
		t.Fatalf("Codec round-trip mismatch: hashEq=%v rp=%d disc=%d", string(gotHash) == string(hash), gotRP, gotDisc)
	}
	if c.Encode(nil, 0, 0) != nil {
		t.Fatal("Codec.Encode must return nil for a nil hash")
	}
}
