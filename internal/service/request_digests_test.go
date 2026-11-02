package service

import (
	"bytes"
	"testing"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestRequestDigests(t *testing.T) {
	c, err := secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: bytes.Repeat([]byte{3}, 32), Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	want, err := c.Digests("e2b.create-fingerprint/v1", []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&Service{cipher: c}).RequestDigests("e2b.create-fingerprint/v1", []byte("body"))
	if err != nil || len(got) != 1 || !bytes.Equal(got[0].Sum, want[0].Sum) {
		t.Fatalf("RequestDigests = %+v, %v; want the cipher's %+v", got, err, want)
	}

	// No server key, no digest: a fingerprint must never fall back to a plain hash.
	for name, s := range map[string]*Service{"nil service": nil, "no cipher": {}} {
		if d, err := s.RequestDigests("p", nil); err == nil {
			t.Fatalf("%s: RequestDigests = %+v, want an error", name, d)
		}
	}
}
