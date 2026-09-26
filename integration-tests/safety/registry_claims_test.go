package safety

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// Every registered use case must be CLAIMED by a test — that is, some test
// under integration-tests/suite must call harness.Require with its id (or
// list it in alsoCovers).
//
// This is not pedantry. report/gen.go joins a run's results to the registry by
// the "ucid=" line that Require logs, and a registered UC that no test ever
// claims is reported as MISSING, which the gate treats as a hard failure. The
// failure arrives at the end of a live AWS run that costs money and an hour,
// naming a bookkeeping mistake. Catching it in `make test` costs nothing.
//
// The reverse direction matters just as much: a test that claims an id the
// registry does not define calls t.Fatalf inside Require ("unknown use case"),
// so a typo'd id fails one case rather than the run — but it fails it for a
// reason that has nothing to do with what it tests.
func TestEveryRegisteredUseCaseIsClaimedByATest(t *testing.T) {
	claimed, declared := scanSuiteClaims(t)

	var unclaimed []string
	for _, uc := range harness.Registry {
		if !uc.Implemented {
			// Implemented:false is an honest PENDING row; it is allowed to
			// have no test. That is the whole point of the field.
			continue
		}
		if !claimed[uc.ID] {
			unclaimed = append(unclaimed, uc.ID)
		}
	}
	if len(unclaimed) > 0 {
		sort.Strings(unclaimed)
		t.Fatalf("registered as Implemented but no test claims them, so a live run reports them MISSING and the gate fails: %s",
			strings.Join(unclaimed, ", "))
	}

	var unknown []string
	for id := range declared {
		if _, ok := harness.Lookup(id); !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		t.Fatalf("tests claim use case ids the registry does not define: %s", strings.Join(unknown, ", "))
	}
}

var (
	// The scenario argument is not always named "sc": suite/sims/gate.go calls
	// it "scenario". Matching the literal name missed that file entirely and
	// reported its UC-108 as unclaimed — which is exactly the false alarm this
	// guard must not produce.
	requireCall = regexp.MustCompile(`harness\.Require\(\s*t\s*,\s*[A-Za-z_][A-Za-z0-9_.]*\s*,\s*((?:"UC-[A-Za-z0-9]+"\s*,?\s*)+)\)`)
	ucLiteral   = regexp.MustCompile(`"(UC-[A-Za-z0-9]+)"`)
)

// scanSuiteClaims returns the set of UC ids any suite test claims. Both
// returned sets are the same thing; two names because the two directions of
// the check read very differently.
//
// It walks the whole suite tree, not just suite/*_test.go: UC-108 is claimed
// from suite/sims/gate.go, a non-test file in a subpackage, and a shallow
// scan of _test.go files reported it as unclaimed.
func scanSuiteClaims(t *testing.T) (map[string]bool, map[string]bool) {
	t.Helper()
	root := filepath.Join("..", "suite")
	claimed := map[string]bool{}
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		files++
		for _, m := range requireCall.FindAllStringSubmatch(string(b), -1) {
			for _, id := range ucLiteral.FindAllStringSubmatch(m[1], -1) {
				claimed[id[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if files == 0 {
		t.Fatal("no suite files were scanned; this guard would pass having checked nothing")
	}
	if len(claimed) == 0 {
		t.Fatalf("scanned %d suite files and found no harness.Require call; the pattern no longer matches how the suite claims use cases", files)
	}
	return claimed, claimed
}
