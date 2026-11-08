//go:build itest_failpoints

package failpoint

import (
	"os"
	"path/filepath"
	"strings"
)

// dir and block are variables only so the unit tests can point Hit at a
// temporary directory and release it instead of hanging the test binary.
var (
	dir   = Dir
	block = func() { select {} }
)

// Hit blocks forever when the failpoint name is armed for a prefix of key.
// An unarmed failpoint costs one failed file read, and only in itest builds.
func Hit(name, key string) {
	// Names are constants at the call sites; refuse anything that could
	// reach outside dir rather than trust that.
	if name == "" || name != filepath.Base(name) {
		return
	}
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	// An empty file matches nothing: a half-written or truncated arm must not
	// hang every create on the node.
	prefix := strings.TrimSpace(string(raw))
	if prefix == "" || !strings.HasPrefix(key, prefix) {
		return
	}
	// Only the caller whose Remove succeeds fires. Two creates matching the
	// same prefix at once would otherwise both hang, and the suite kills one
	// process for one hit.
	if os.Remove(path) != nil {
		return
	}
	// Without the marker nobody learns this process is parked and nobody
	// kills it, so a failed write must not block.
	if os.WriteFile(path+HitSuffix, []byte(key+"\n"), 0o600) != nil {
		return
	}
	block()
}
