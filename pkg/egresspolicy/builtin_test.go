package egresspolicy

import (
	"errors"
	"strings"
	"testing"
)

// TestBuiltinCatalogueIsValid: every version of every built-in compiles in
// the shared grammar and fits one profile's cap.
func TestBuiltinCatalogueIsValid(t *testing.T) {
	for name, versions := range builtinCatalogue {
		if !ValidProfileName(name) {
			t.Fatalf("built-in name %q", name)
		}
		for v, entries := range versions {
			if v < 20000101 || v > 99991231 {
				t.Fatalf("%s@%d: versions are YYYYMMDD", name, v)
			}
			if _, err := ParseAllowList("builtin", entries, MaxProfileHostnames); err != nil {
				t.Fatalf("%s@%d: %v", name, v, err)
			}
		}
	}
}

func TestResolveBuiltin(t *testing.T) {
	p, err := ResolveBuiltin("builtin:pypi")
	if err != nil || p.Ref != "builtin:pypi@20261006" || p.Version != 20261006 || len(p.AllowOut) == 0 {
		t.Fatalf("bare = %+v %v", p, err)
	}
	pinned, err := ResolveBuiltin(p.Ref)
	if err != nil || pinned.Ref != p.Ref {
		t.Fatalf("pinned = %+v %v", pinned, err)
	}
	// Newer than this catalogue: a newer node's pin, not a typo.
	if _, err := ResolveBuiltin("builtin:pypi@29991231"); !errors.Is(err, ErrBuiltinVersionMissing) {
		t.Fatalf("newer version: %v", err)
	}
	for _, bad := range []string{"builtin:nope", "builtin:pypi@abc", "builtin:pypi@20200101", "org:x", "pypi"} {
		if _, err := ResolveBuiltin(bad); !errors.Is(err, ErrBuiltinUnknown) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	if names := strings.Join(BuiltinNames(), ","); !strings.HasPrefix(names, "apt-ubuntu,crates,docker-hub") {
		t.Fatalf("names = %s", names)
	}
}
