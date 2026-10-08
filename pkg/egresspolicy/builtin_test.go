package egresspolicy

import (
	"errors"
	"slices"
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

// TestBuiltinDockerHubCoversBlobRedirects: the latest docker-hub version
// lists the hosts Docker Hub redirects blob downloads to (a live crane pull
// from AWS failed without its S3 host), and the version it replaced is
// unchanged for sandboxes pinned to it.
func TestBuiltinDockerHubCoversBlobRedirects(t *testing.T) {
	p, err := ResolveBuiltin("builtin:docker-hub")
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 20261008 {
		t.Fatalf("latest docker-hub = %d", p.Version)
	}
	for _, h := range []string{
		"docker-images-prod.s3.dualstack.us-east-1.amazonaws.com",
		"docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
	} {
		if !slices.Contains(p.AllowOut, h) {
			t.Errorf("docker-hub@%d is missing %s", p.Version, h)
		}
	}
	old, err := ResolveBuiltin("builtin:docker-hub@20261006")
	if err != nil || len(old.AllowOut) != 4 || slices.Contains(old.AllowOut, "docker-images-prod.s3.dualstack.us-east-1.amazonaws.com") {
		t.Fatalf("a pinned version must not change: %v %v", old.AllowOut, err)
	}
	if _, err := Compile(Spec{AllowOut: p.AllowOut}); err != nil {
		t.Fatalf("the new version must compile: %v", err)
	}
}
