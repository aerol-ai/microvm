package safety

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// UC-169's hit parser is the one place in this suite where a bug produces a
// FALSE POSITIVE secret leak — the worst output a security suite can give,
// because it sends someone hunting a breach that did not happen.
//
// The live run did exactly that: ssh's "Warning: Permanently added ..."
// banner is non-empty and does not contain NOHITS, so the old
// `out != "" && !strings.Contains(out, "NOHITS")` test reported the canary as
// on disk in all five encodings.
//
// leak_sweep_test.go is behind the `integration` tag so it cannot be linked
// here. Asserting the SHAPE of the parser is what stops the old predicate
// coming back.
func TestLeakSweepParsesHitsRatherThanNonEmptiness(t *testing.T) {
	path := filepath.Join("..", "suite", "leak_sweep_test.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(b)

	if !strings.Contains(src, "func leakHitLines(") {
		t.Fatal("leak_sweep_test.go no longer defines leakHitLines; the sweep must classify lines, not test the output for non-emptiness")
	}
	// The regression predicate, in any spacing.
	bad := regexp.MustCompile(`!strings\.Contains\(\s*\w+\s*,\s*"NOHITS"\s*\)`)
	if bad.Match(b) {
		t.Fatal(`leak_sweep_test.go is back to treating "non-empty and not NOHITS" as a hit. ssh's stderr banner satisfies that and the sweep reports a secret leak that did not happen.`)
	}
	// A hit must come from an explicit marker the remote script emits, so
	// that anything else on the wire — banners, grep diagnostics, sudo
	// chatter — cannot be reported as leaked secret material.
	if !strings.Contains(src, `"HIT:"`) {
		t.Fatal("leakHitLines no longer keys off the HIT: marker; without it, any unexpected output is a reported leak")
	}
	// And an incomplete sweep must fail rather than read as clean.
	if !strings.Contains(src, "SWEEPDONE") {
		t.Fatal("the sweep no longer checks its completion sentinel; a truncated sweep would report zero hits, which is the silent direction of the same bug")
	}
}
