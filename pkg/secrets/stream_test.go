package secrets

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func sealStream(t *testing.T, c *Cipher, aad, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewSealWriter(&out, c, aad)
	if err != nil {
		t.Fatal(err)
	}
	// Uneven writes, so chunk edges fall inside them.
	for len(plain) > 0 {
		n := min(len(plain), 10_000)
		if _, err := w.Write(plain[:n]); err != nil {
			t.Fatal(err)
		}
		plain = plain[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func openStream(c *Cipher, aad, sealed []byte) ([]byte, error) {
	r, err := NewOpenReader(bytes.NewReader(sealed), c, aad)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestSealedStreamRoundTrip(t *testing.T) {
	c := testCipher(t)
	aad := []byte("move|sb-1|inc-1|worker-b")
	for _, size := range []int{0, 1, streamChunk - 1, streamChunk, streamChunk + 1, 3*streamChunk + 17} {
		plain := make([]byte, size)
		_, _ = rand.Read(plain)
		got, err := openStream(c, aad, sealStream(t, c, aad, plain))
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: %d bytes back, err %v", size, len(got), err)
		}
	}
}

// What a stream must refuse: another binding, another key, a stream cut
// short, a chunk changed, two chunks swapped, and something that is not a
// stream at all.
func TestSealedStreamRefuses(t *testing.T) {
	c := testCipher(t)
	aad := []byte("move|sb-1|inc-1|worker-b")
	plain := bytes.Repeat([]byte("memory "), 3*streamChunk/7+100)
	sealed := sealStream(t, c, aad, plain)
	hdr := 8 + int(sealedKeyLen(sealed)) + 4
	chunk := 4 + streamChunk + 16

	other, err := NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	swapped := append([]byte(nil), sealed...)
	copy(swapped[hdr:hdr+chunk], sealed[hdr+chunk:hdr+2*chunk])
	copy(swapped[hdr+chunk:hdr+2*chunk], sealed[hdr:hdr+chunk])
	changed := append([]byte(nil), sealed...)
	changed[hdr+100] ^= 1

	for _, tc := range []struct {
		name   string
		c      *Cipher
		aad    string
		sealed []byte
		want   error
	}{
		{"for another worker", c, "move|sb-1|inc-1|worker-c", sealed, nil},
		{"another key", other, string(aad), sealed, nil},
		{"cut after a chunk", c, string(aad), sealed[:hdr+chunk], ErrStreamTruncated},
		{"cut inside a chunk", c, string(aad), sealed[:hdr+chunk+10], ErrStreamTruncated},
		{"the last chunk dropped", c, string(aad), sealed[:len(sealed)-(4+len(plain)%streamChunk+16)], ErrStreamTruncated},
		{"a chunk changed", c, string(aad), changed, nil},
		{"two chunks swapped", c, string(aad), swapped, nil},
		{"not a stream", c, string(aad), []byte("plain text, not sealed"), nil},
	} {
		got, err := openStream(tc.c, []byte(tc.aad), tc.sealed)
		if err == nil {
			t.Fatalf("%s: opened %d bytes", tc.name, len(got))
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}

	// A writer never closed has no last chunk: it does not open.
	var out bytes.Buffer
	w, _ := NewSealWriter(&out, c, aad)
	_, _ = w.Write(plain)
	if _, err := openStream(c, aad, out.Bytes()); !errors.Is(err, ErrStreamTruncated) {
		t.Fatalf("an unclosed stream: err = %v, want ErrStreamTruncated", err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if _, err := w.Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "after close") {
		t.Fatalf("write after close: %v", err)
	}
	if _, err := NewSealWriter(&out, nil, aad); err == nil {
		t.Fatal("a stream with no cipher was started")
	}
	if _, err := NewOpenReader(bytes.NewReader(sealed), nil, aad); err == nil {
		t.Fatal("a stream was opened with no cipher")
	}
}

func sealedKeyLen(sealed []byte) uint32 {
	return uint32(sealed[4])<<24 | uint32(sealed[5])<<16 | uint32(sealed[6])<<8 | uint32(sealed[7])
}
