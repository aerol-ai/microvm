package wasmmod

import (
	"path/filepath"
	"strings"
	"testing"
)

// A relative module ref must stay under ModulesDir; "../" traversal is never a
// legitimate module location and must be rejected before it becomes a path.
// Absolute paths remain the explicit operator escape hatch and still resolve.
func TestResolvePathRejectsRelativeTraversal(t *testing.T) {
	dir := t.TempDir()
	r := NewResolver(dir)

	bad := []string{
		"../escape.wasm",
		"../../etc/passwd",
		"a/../../escape.wasm",
		"sub/../../../escape.wasm",
		"file://../escape.wasm",
	}
	for _, ref := range bad {
		t.Run(ref, func(t *testing.T) {
			got, err := r.resolvePath(ref)
			if err == nil {
				t.Fatalf("resolvePath(%q) = %q, nil; want escape rejection", ref, got)
			}
			if !strings.Contains(err.Error(), "escapes modules dir") {
				t.Fatalf("resolvePath(%q) error = %v; want escapes-modules-dir", ref, err)
			}
		})
	}

	// Legitimate refs still resolve under ModulesDir.
	for _, ref := range []string{"hello.wasm", "sub/dir/mod.wasm", "./mod.wasm"} {
		p, err := r.resolvePath(ref)
		if err != nil {
			t.Fatalf("resolvePath(%q) = %v; want ok", ref, err)
		}
		base := filepath.Clean(dir)
		if p != base && !strings.HasPrefix(p, base+string(filepath.Separator)) {
			t.Fatalf("resolvePath(%q) = %q escaped %q", ref, p, base)
		}
	}

	// Absolute paths (operator escape hatch) are returned as-is, unaffected.
	abs := filepath.Join(dir, "elsewhere.wasm")
	if p, err := r.resolvePath(abs); err != nil || p != abs {
		t.Fatalf("resolvePath(abs) = %q, %v; want %q, nil", p, err, abs)
	}
}
