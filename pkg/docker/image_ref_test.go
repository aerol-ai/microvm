package docker

import (
	"slices"
	"testing"
)

func TestLooksLikeImageID(t *testing.T) {
	for ref, want := range map[string]bool{
		"sha256:4f1a":    true,
		"SHA256:4F1A":    true,
		"4f1a":           true,
		"0":              true,
		" deadbeef ":     true,
		"":               false,
		"ubuntu":         false,
		"cafe:1.0":       false,
		"team/cafe":      false,
		"DEADBEEF":       false, // not a valid id or name; the engine rejects it
		"abc@sha256:00":  false,
		"registry/4f1a":  false,
		"4f1a.local/img": false,
	} {
		if got := LooksLikeImageID(ref); got != want {
			t.Errorf("LooksLikeImageID(%q) = %v, want %v", ref, got, want)
		}
	}
}

func TestEquivalentImageNames(t *testing.T) {
	for _, tc := range []struct {
		ref     string
		include []string
		count   int
	}{
		{"snap", []string{"snap", "snap:latest", "library/snap", "docker.io/library/snap:latest", "index.docker.io/library/snap"}, 12},
		{"snap:v2", []string{"snap:v2", "docker.io/library/snap:v2", "library/snap:v2"}, 6},
		{"docker.io/library/snap:latest", []string{"snap", "snap:latest"}, 12},
		{"team/snap", []string{"team/snap", "team/snap:latest", "docker.io/team/snap"}, 6},
		{"registry.example.com/team/snap", []string{"registry.example.com/team/snap", "registry.example.com/team/snap:latest"}, 2},
		{"snap@sha256:" + "0000000000000000000000000000000000000000000000000000000000000000", nil, 1},
		{"Not A Ref", nil, 1},
	} {
		got := EquivalentImageNames(tc.ref)
		if got[0] != tc.ref {
			t.Errorf("%q: first name %q, want the ref itself", tc.ref, got[0])
		}
		if len(got) != tc.count {
			t.Errorf("%q: %d names %v, want %d", tc.ref, len(got), got, tc.count)
		}
		for _, name := range tc.include {
			if !slices.Contains(got, name) {
				t.Errorf("%q: names %v miss %q", tc.ref, got, name)
			}
		}
	}
}
