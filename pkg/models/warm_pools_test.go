package models

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateWarmPoolImage(t *testing.T) {
	for _, tc := range []struct {
		image string
		ok    bool
	}{
		{"python:3.12", true},
		{"ghcr.io/acme/agent:1", true},
		{"localhost:5000/x/y@sha256:abc", true},
		{"", false},
		{"   ", false},
		{" python:3.12", false},
		{"python:3.12\n", false},
		{"https://ghcr.io/acme/agent", false},
		{"py thon", false},
		{"py\x00thon", false},
		{"/python", false},
		{"python/", false},
		{"ghcr.io//agent", false},
		{strings.Repeat("a", maxWarmPoolImageLen+1), false},
	} {
		err := ValidateWarmPoolImage(tc.image)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateWarmPoolImage(%q) = %v, want ok=%v", tc.image, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrWarmPoolInvalid) {
			t.Errorf("ValidateWarmPoolImage(%q) = %v, want ErrWarmPoolInvalid", tc.image, err)
		}
	}
}

func TestWarmPoolRequestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  WarmPoolRequest
		ok   bool
	}{
		{"fixed 0", WarmPoolRequest{}, true},
		{"fixed 1", WarmPoolRequest{Depth: 1}, true},
		{"fixed at the limit", WarmPoolRequest{Depth: MaxWarmPoolDepth}, true},
		{"negative depth", WarmPoolRequest{Depth: -1}, false},
		{"depth past the limit", WarmPoolRequest{Depth: MaxWarmPoolDepth + 1}, false},
		{"demand down to zero", WarmPoolRequest{MaxDepth: 4}, true},
		{"demand with a floor", WarmPoolRequest{MinDepth: 1, MaxDepth: 4}, true},
		{"demand pinned to one size", WarmPoolRequest{MinDepth: 3, MaxDepth: 3}, true},
		{"min above max", WarmPoolRequest{MinDepth: 5, MaxDepth: 4}, false},
		{"min without max", WarmPoolRequest{MinDepth: 1}, false},
		{"depth and a range", WarmPoolRequest{Depth: 2, MaxDepth: 4}, false},
		{"negative min", WarmPoolRequest{MinDepth: -1, MaxDepth: 4}, false},
		{"max past the limit", WarmPoolRequest{MaxDepth: MaxWarmPoolDepth + 1}, false},
	} {
		err := tc.req.Validate()
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrWarmPoolInvalid)) {
			t.Errorf("%s: %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	if (WarmPool{Depth: 3}).FollowsDemand() || !(WarmPool{MaxDepth: 1}).FollowsDemand() {
		t.Fatal("FollowsDemand is MaxDepth > 0")
	}
}
