package egresspolicy

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Built-in profiles (plans/egress-domain-filtering.md P2-8, CEO D3, D11): a
// versioned catalogue of the hosts common package managers and registries
// use. A reference is pinned at create to builtin:<name>@<YYYYMMDD>, so a
// sandbox's reachable hosts never change underneath it; owners move to a
// newer list by updating the policy. Every version ever shipped stays in the
// catalogue, so failover and reconcile reproduce the same list on any node
// that has it.

// ErrBuiltinUnknown is a reference to a built-in profile that doesn't exist
// (400).
var ErrBuiltinUnknown = errors.New("unknown built-in egress profile")

// ErrBuiltinVersionMissing is a pinned version newer than this node's
// catalogue, as on an older node during a rolling upgrade. The sandbox fails
// closed until it lands on a node that has it. An older version a node
// doesn't have never existed, since no version is ever removed.
var ErrBuiltinVersionMissing = errors.New("built-in egress profile version is not in this node's catalogue")

// builtinCatalogue maps each profile to its versions. Add a version, never
// edit one: a pinned sandbox must get exactly the list it was created with.
var builtinCatalogue = map[string]map[int64][]string{
	"pypi": {20261006: {
		"pypi.org", "files.pythonhosted.org",
	}},
	"npm": {20261006: {
		"registry.npmjs.org", "registry.yarnpkg.com",
	}},
	"github": {20261006: {
		// githubusercontent.com is a public suffix, so its hosts are listed
		// rather than wildcarded.
		"github.com", "*.github.com", "github.com:22", "raw.githubusercontent.com",
		"objects.githubusercontent.com", "codeload.github.com", "ghcr.io", "pkg-containers.githubusercontent.com",
	}},
	"huggingface": {20261006: {
		"huggingface.co", "*.huggingface.co", "*.hf.co",
	}},
	"golang-proxy": {20261006: {
		"proxy.golang.org", "sum.golang.org", "storage.googleapis.com",
	}},
	"crates": {20261006: {
		"crates.io", "*.crates.io",
	}},
	"apt-ubuntu": {20261006: {
		"archive.ubuntu.com", "*.archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com",
	}},
	"docker-hub": {20261006: {
		"registry-1.docker.io", "auth.docker.io", "index.docker.io", "production.cloudflare.docker.com",
	}},
}

// BuiltinProfile is one resolved built-in profile version.
type BuiltinProfile struct {
	// Ref is the pinned reference, builtin:<name>@<version>.
	Ref      string
	Name     string
	Version  int64
	AllowOut []string
}

// ResolveBuiltin resolves builtin:<name> (to the latest version) or
// builtin:<name>@<version>.
func ResolveBuiltin(ref string) (BuiltinProfile, error) {
	rest, ok := strings.CutPrefix(ref, BuiltinProfilePrefix)
	if !ok {
		return BuiltinProfile{}, fmt.Errorf("%w: %q is not a builtin: reference", ErrBuiltinUnknown, ref)
	}
	name, ver, pinned := strings.Cut(rest, "@")
	versions, ok := builtinCatalogue[name]
	if !ok {
		return BuiltinProfile{}, fmt.Errorf("%w: %q (built-ins are %s)", ErrBuiltinUnknown, name, strings.Join(BuiltinNames(), ", "))
	}
	var latest int64
	for v := range versions {
		latest = max(latest, v)
	}
	version := latest
	if pinned {
		v, err := strconv.ParseInt(ver, 10, 64)
		if err != nil {
			return BuiltinProfile{}, fmt.Errorf("%w: %q: versions are YYYYMMDD", ErrBuiltinUnknown, ref)
		}
		if _, ok := versions[v]; !ok {
			if v > latest {
				return BuiltinProfile{}, fmt.Errorf("%w: %s (newest here is %d)", ErrBuiltinVersionMissing, ref, latest)
			}
			return BuiltinProfile{}, fmt.Errorf("%w: %s: no such version", ErrBuiltinUnknown, ref)
		}
		version = v
	}
	return BuiltinProfile{
		Ref:      fmt.Sprintf("%s%s@%d", BuiltinProfilePrefix, name, version),
		Name:     name,
		Version:  version,
		AllowOut: append([]string(nil), versions[version]...),
	}, nil
}

// BuiltinNames lists the built-in profiles, sorted.
func BuiltinNames() []string {
	names := make([]string, 0, len(builtinCatalogue))
	for n := range builtinCatalogue {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
