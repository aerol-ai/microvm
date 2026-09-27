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

// The sweep must never put the canary on the remote command line.
//
// sudo logs the full command line to /var/log/auth.log and the journal, so a
// needle in argv is written into the exact files the sweep then searches.
// The live run reported the canary "on disk" in all five encodings and every
// location was /var/log/auth.log — put there by the sweep itself. A
// self-inflicted false-positive leak is indistinguishable from a real one
// until someone reads the paths.
func TestLeakSweepPassesTheNeedleOnStdin(t *testing.T) {
	for _, f := range []string{"leak_sweep_test.go", "secrets_support_test.go"} {
		b, err := os.ReadFile(filepath.Join("..", "suite", f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(b)
		if !strings.Contains(src, "leakGrepScript") {
			continue
		}
		// leakGrepScript must be a constant, not a function taking the needle:
		// a parameter is how it ended up in argv.
		if regexp.MustCompile(`func leakGrepScript\(`).MatchString(src) {
			t.Fatalf("%s builds the sweep command from the needle; sudo will log it to auth.log and the sweep will find its own canary", f)
		}
		if strings.Contains(src, "leakGrepScript") && strings.Contains(src, "harness.SSHRun(") &&
			regexp.MustCompile(`harness\.SSHRun\([^)]*leakGrepScript`).MatchString(src) {
			t.Fatalf("%s runs the sweep without stdin; the needle must be fed to grep -f - so it never reaches the remote argv", f)
		}
	}
}

// The journal arm must report only THAT it matched, never the matching
// lines: those contain the secret, and printing them as "locations" puts it
// in a CI log — the thing this case exists to prevent.
func TestLeakSweepNeverPrintsJournalContent(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "suite", "secrets_support_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "leakGrepScript")
	if i < 0 {
		t.Fatal("leakGrepScript is gone")
	}
	// Bound the window to the script definition.
	window := src[i:min(len(src), i+2000)]
	if !strings.Contains(window, "grep -qaF") {
		t.Fatal("the journal arm no longer uses grep -q; it would emit matching lines, and those contain the secret")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
