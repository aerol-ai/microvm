package docker

import (
	"slices"
	"strings"
	"testing"

	"github.com/distribution/reference"
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

// A snapshot's tag is a function of its name's canonical spelling: one tag
// for every spelling of one name (the catalog's one snapshot), a different
// tag for any other name, always in the snapshot namespace, local only, and
// a valid reference.
func TestSnapshotImageTag(t *testing.T) {
	same := []string{"snap", "snap:latest", "docker.io/library/snap", " index.docker.io/library/snap:latest "}
	tag := SnapshotImageTag(same[0])
	for _, name := range same[1:] {
		if got := SnapshotImageTag(name); got != tag {
			t.Errorf("SnapshotImageTag(%q) = %q, want %q like %q", name, got, tag, same[0])
		}
	}
	seen := map[string]string{}
	for _, name := range []string{"snap", "snap:v1", "snap:v2", "Snap", "python", "runloop/0123:latest", "ghcr.io/org/snap", "x@sha256:" + strings.Repeat("a", 64)} {
		got := SnapshotImageTag(name)
		if other, dup := seen[got]; dup {
			t.Errorf("%q and %q share %q", other, name, got)
		}
		seen[got] = name
		if !IsSnapshotImageRef(got) || !IsLocalOnlyImageRef(got) {
			t.Errorf("SnapshotImageTag(%q) = %q, not a local snapshot image", name, got)
		}
		if _, err := reference.ParseNormalizedNamed(got); err != nil {
			t.Errorf("SnapshotImageTag(%q) = %q: %v", name, got, err)
		}
	}
}

// Every spelling the engine resolves to the snapshot namespace counts;
// other registries, look-alike namespaces and the "snapshots/" names callers
// already use do not.
func TestIsSnapshotImageRef(t *testing.T) {
	for ref, want := range map[string]bool{
		"aerolvm-snapshot/abc:latest":                  true,
		"docker.io/aerolvm-snapshot/abc":               true,
		" index.docker.io/aerolvm-snapshot/abc:latest": true,
		"ghcr.io/aerolvm-snapshot/abc":                 false,
		"aerolvm-snapshots/abc":                        false,
		"snapshots/demo:v1":                            false,
		"python":                                       false,
		"Not A Ref":                                    false,
		"":                                             false,
	} {
		if got := IsSnapshotImageRef(ref); got != want {
			t.Errorf("IsSnapshotImageRef(%q) = %v, want %v", ref, got, want)
		}
	}
	if !IsLocalOnlyImageRef("snapshots/demo:v1") {
		t.Error("snapshots committed under snapshots/ names must stay local only")
	}
}
