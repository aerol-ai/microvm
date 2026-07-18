// Package jsbundle resolves and stores the JS/TS bundles that back
// runtime=isolate sandboxes (plans/isolate-runtime.md §7, the analog of
// pkg/wasmmod for .wasm modules). A "bundle" is the code a workerd isolate
// runs: a set of ES modules plus the name of the entry module and the pinned
// workerd compatibility date. Bundles are content-addressed — the sha256 over
// a canonical serialization is the identity that makes create idempotent (a
// retry resolves to the same digest and joins the existing sandbox) and lets
// the store deduplicate and reference-count.
package jsbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// DefaultMainModule is the entry module name assumed when a bundle is resolved
// from a single source file.
const DefaultMainModule = "main.js"

// DefaultCompatibilityDate pins workerd's behavior for a bundle that does not
// name one. Bundles SHOULD pin their own — this is the floor so an engine
// upgrade never silently changes a bundle's semantics (plans/isolate-runtime.md
// §9). Kept conservative and bumped deliberately.
const DefaultCompatibilityDate = "2026-01-01"

// Bundle is the resolved code for one isolate: the module map (name → source),
// the entry module, and the pinned compatibility date. It is exactly the shape
// the workerd controller's dynamic-load provider needs (§2.2 spike): the host
// wrapper serializes this into the WorkerLoader source.
type Bundle struct {
	// MainModule is the entry module name; it MUST be a key in Modules.
	MainModule string `json:"main_module"`
	// Modules maps module name → ES module source. At least one entry.
	Modules map[string]string `json:"modules"`
	// CompatibilityDate pins workerd behavior (Workers versioning).
	CompatibilityDate string `json:"compatibility_date"`
	// Digest is the sha256 (hex, no prefix) over the canonical serialization;
	// set by ComputeDigest / the store, empty on a freshly-built bundle.
	Digest string `json:"-"`
}

// canonicalBytes is the digest preimage: a deterministic JSON encoding with
// module names sorted, so the same logical bundle always hashes identically
// regardless of map iteration order.
func (b *Bundle) canonicalBytes() ([]byte, error) {
	names := make([]string, 0, len(b.Modules))
	for name := range b.Modules {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make([][2]string, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, [2]string{name, b.Modules[name]})
	}
	return json.Marshal(struct {
		MainModule        string      `json:"main_module"`
		CompatibilityDate string      `json:"compatibility_date"`
		Modules           [][2]string `json:"modules"`
	}{b.MainModule, b.CompatibilityDate, ordered})
}

// ComputeDigest fills Digest from the canonical serialization and returns it.
func (b *Bundle) ComputeDigest() (string, error) {
	raw, err := b.canonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	b.Digest = hex.EncodeToString(sum[:])
	return b.Digest, nil
}

// Validate enforces the invariants every stored/injected bundle must hold:
// a non-empty main module that exists in a non-empty module map, and a
// compatibility date. It does NOT validate JS syntax — workerd is the arbiter
// of that at load time; this is the cheap structural gate before we persist or
// inject.
func (b *Bundle) Validate() error {
	if b.MainModule == "" {
		return fmt.Errorf("%w: main module is empty", ErrInvalidBundle)
	}
	if len(b.Modules) == 0 {
		return fmt.Errorf("%w: bundle has no modules", ErrInvalidBundle)
	}
	if _, ok := b.Modules[b.MainModule]; !ok {
		return fmt.Errorf("%w: main module %q is not present in modules", ErrInvalidBundle, b.MainModule)
	}
	for name, src := range b.Modules {
		if name == "" {
			return fmt.Errorf("%w: a module has an empty name", ErrInvalidBundle)
		}
		if src == "" {
			return fmt.Errorf("%w: module %q has empty source", ErrInvalidBundle, name)
		}
	}
	if b.CompatibilityDate == "" {
		return fmt.Errorf("%w: compatibility_date is empty", ErrInvalidBundle)
	}
	return nil
}

// SizeBytes is the total source size across modules — the quantity the store's
// size cap and per-tenant quota are enforced against.
func (b *Bundle) SizeBytes() int64 {
	var n int64
	for _, src := range b.Modules {
		n += int64(len(src))
	}
	return n
}
