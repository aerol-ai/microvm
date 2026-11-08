//go:build !itest_failpoints

package failpoint

import (
	"os"
	"path/filepath"
	"testing"
)

// Without the tag Hit is the release behaviour: it returns at once whatever
// the arguments, reads nothing and allocates nothing.
func TestHitIsANoOpWithoutTheTag(t *testing.T) {
	if allocs := testing.AllocsPerRun(1000, func() { Hit(CreateBeforePersist, "chaos-480-x") }); allocs != 0 {
		t.Fatalf("Hit allocates %.0f times per call in a build without failpoints", allocs)
	}
	// Even a matching arm where an itest build would look must not fire.
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, CreateBeforePersist), []byte("chaos-"), 0o600); err != nil {
		t.Fatal(err)
	}
	Hit(filepath.Join(d, CreateBeforePersist), "chaos-480-x")
	if _, err := os.Stat(filepath.Join(d, CreateBeforePersist+HitSuffix)); err == nil {
		t.Fatal("a build without failpoints wrote a hit marker")
	}
}
