package jsbundle

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestIsFileRef(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{"file:///tmp/w.js", true},
		{"/tmp/w.js", true},
		{"./x.mjs", true},
		{"Worker.ts", true},
		{"sha256:" + strings.Repeat("a", 64), false},
		{"uploaded-name", false},
		{"  file:///tmp/w.js  ", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsFileRef(tc.ref); got != tc.want {
			t.Fatalf("IsFileRef(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestAsDigestAndIsHex64Edges(t *testing.T) {
	// sha256: prefix with non-hex / wrong length must not look like a digest.
	if _, ok := asDigest("sha256:deadbeef"); ok {
		t.Fatal("short sha256: suffix must not be a digest")
	}
	bad := "sha256:" + strings.Repeat("g", 64)
	if _, ok := asDigest(bad); ok {
		t.Fatal("non-hex sha256: suffix must not be a digest")
	}
	// Uppercase hex is rejected (digests are lowercase).
	if isHex64(strings.Repeat("A", 64)) {
		t.Fatal("uppercase hex must fail isHex64")
	}
	if isHex64(strings.Repeat("a", 63) + "g") {
		t.Fatal("non-hex char must fail isHex64")
	}
}

func TestResolverSha256BadHex(t *testing.T) {
	r := NewResolver(nil)
	// Not a digest (bad hex) → falls through to name lookup → ErrBundleNotFound.
	ref := "sha256:" + strings.Repeat("z", 64)
	if _, err := r.Resolve(context.Background(), "", ref); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("bad sha256 ref err = %v, want ErrBundleNotFound", err)
	}
}
