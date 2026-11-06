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
		depth int
		ok    bool
	}{
		{0, true}, {1, true}, {MaxWarmPoolDepth, true}, {-1, false}, {MaxWarmPoolDepth + 1, false},
	} {
		err := WarmPoolRequest{Depth: tc.depth}.Validate()
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrWarmPoolInvalid)) {
			t.Errorf("depth %d: %v, want ok=%v", tc.depth, err, tc.ok)
		}
	}
}
