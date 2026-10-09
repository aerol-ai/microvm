package procid

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveInRootFailures: a sandbox root that is gone, and a path that
// isn't in the sandbox, are errors rather than a zero FileID that could
// compare equal to another miss.
func TestResolveInRootFailures(t *testing.T) {
	root := t.TempDir()
	if _, err := resolveInRoot(filepath.Join(root, "gone"), "/usr/bin/git"); err == nil || !strings.Contains(err.Error(), "sandbox root") {
		t.Fatalf("missing root: %v", err)
	}
	if _, err := resolveInRoot(root, "/usr/bin/git"); err == nil || !strings.Contains(err.Error(), "in the sandbox") {
		t.Fatalf("missing path: %v", err)
	}
}
