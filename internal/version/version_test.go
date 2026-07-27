package version

import "testing"

func TestVersionDefault(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must be non-empty (linker -X override or \"dev\")")
	}
}
