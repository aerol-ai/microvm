package wasmmod

import (
	"os"
	"path/filepath"
	"testing"
)

// ResolveByDigest returns the frozen cached copy, ignoring any alias retarget.
// This is the byte-freezing half of the codex C2 fix: a sandbox that pinned a
// digest at create boots those exact bytes on restart even if its alias now
// points elsewhere.
func TestResolveByDigestCacheHit(t *testing.T) {
	mr := newTestModuleResolver(t)
	// Simulate a previously-pulled module published in the content cache.
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	digest, _, err := fileDigest(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	frozen := filepath.Join(mr.CacheDir, digest+".wasm")
	copyFile(t, src, frozen)

	got, ok := mr.ResolveByDigest(digest)
	if !ok {
		t.Fatalf("expected cache hit for %s", digest)
	}
	if got.Path != frozen || got.Digest != digest {
		t.Fatalf("unexpected: %+v", got)
	}
}

// A digest with no frozen copy misses, so the caller falls back to ref
// resolution (and its drift assertion).
func TestResolveByDigestMiss(t *testing.T) {
	mr := newTestModuleResolver(t)
	if _, ok := mr.ResolveByDigest("deadbeef"); ok {
		t.Fatal("expected miss for uncached digest")
	}
	if _, ok := mr.ResolveByDigest(""); ok {
		t.Fatal("empty digest must miss")
	}
}

// The manifest→content pointer lets a repeat resolve of a mutable tag hit the
// cache after only a cheap credentialed manifest resolve — no blob download.
// This is the steady-state half of the codex P0 single-flight fix.
func TestManifestPointerRoundTrip(t *testing.T) {
	mr := newTestModuleResolver(t)
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	digest, _, err := fileDigest(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mr.CacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	copyFile(t, src, filepath.Join(mr.CacheDir, digest+".wasm"))

	const manifestDigest = "sha256:manifestabc"
	// Before the pointer exists, the manifest lookup misses.
	if _, ok := mr.lookupByManifest(manifestDigest); ok {
		t.Fatal("expected miss before pointer written")
	}
	mr.writeManifestPointer(manifestDigest, digest)
	got, ok := mr.lookupByManifest(manifestDigest)
	if !ok {
		t.Fatalf("expected hit after pointer written")
	}
	if got.Digest != digest {
		t.Fatalf("pointer resolved to %q, want %q", got.Digest, digest)
	}
	// A pointer whose content file was evicted must miss (and trigger a re-pull),
	// never return a dangling path.
	if err := os.Remove(filepath.Join(mr.CacheDir, digest+".wasm")); err != nil {
		t.Fatal(err)
	}
	if _, ok := mr.lookupByManifest(manifestDigest); ok {
		t.Fatal("expected miss after content file evicted")
	}
}

func TestLookupByManifestRejectsBlankPointer(t *testing.T) {
	mr := newTestModuleResolver(t)
	if err := os.MkdirAll(filepath.Join(mr.CacheDir, ".manifest"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mr.manifestPointer("sha256:blank"), []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := mr.lookupByManifest("sha256:blank"); ok {
		t.Fatal("blank pointer must miss")
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
