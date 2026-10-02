package wasmmod

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzResolvePathNoEscape asserts that a resolved RELATIVE module ref never
// escapes ModulesDir. Absolute paths are the explicit operator escape hatch and
// are intentionally excluded.
func FuzzResolvePathNoEscape(f *testing.F) {
	for _, s := range []string{"a.wasm", "sub/a.wasm", "../x", "../../etc/x", "file://../x", "./a.wasm", "a/../../x"} {
		f.Add(s)
	}
	dir := f.TempDir()
	r := NewResolver(dir)
	base := filepath.Clean(dir)
	f.Fuzz(func(t *testing.T, ref string) {
		p, err := r.resolvePath(ref)
		if err != nil {
			return // rejected
		}
		if filepath.IsAbs(strings.TrimPrefix(ref, "file://")) {
			return // absolute operator escape hatch, allowed by design
		}
		if p != base && !strings.HasPrefix(p, base+string(filepath.Separator)) {
			t.Fatalf("resolvePath(%q) = %q escaped %q", ref, p, base)
		}
	})
}
