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
	// Claim by renaming the arm onto the marker. A rename moves a name
	// exactly once, so of several creates matching at the same moment only
	// one fires (the suite kills one process for one hit), and the marker
	// exists the instant it does. Removing the arm would not do: two unlinks
	// of one path can both succeed on some filesystems (APFS does it under
	// contention). A rename that fails left no marker, so nobody would know
	// to kill this process: don't block.
	marker := path + HitSuffix
	if os.Rename(path, marker) != nil {
		return
	}
	// The key says which create parked; the marker's existence alone says
	// which node to kill, so a failed write still blocks.
	_ = os.WriteFile(marker, []byte(key+"\n"), 0o600)
	block()
}
