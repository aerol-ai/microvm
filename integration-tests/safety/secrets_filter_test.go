package safety

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// `make integration-secrets-only` re-runs just the security use cases against
// an already-provisioned cluster. Its filter is a Go -run regex, and a filter
// that under-runs is the worst possible failure mode for that target: it
// reports a green partial pass over tests that never executed.
//
// The first version was a fuzzy name pattern (Secret|Audit|Jail|…). It missed
// a third of the cases — TestGetAndListOmitEnvByDefault,
// TestEnterpriseBootGateMatrix, TestFleetScaleReadsStayPaged and others — and
// swept in unrelated ones. So the regex is generated and this test is what
// keeps it honest.
func TestSecretsTestFilterCoversEverySecurityTest(t *testing.T) {
	fileList := readLines(t, filepath.Join("..", "lib", "secrets-test-files.txt"))
	if len(fileList) == 0 {
		t.Fatal("secrets-test-files.txt is empty; the filter would be generated from nothing")
	}

	funcRe := regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\)`)
	var names []string
	for _, f := range fileList {
		path := filepath.Join("..", "suite", f)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v (listed in secrets-test-files.txt but missing — rename it there too)", path, err)
		}
		for _, m := range funcRe.FindAllStringSubmatch(string(b), -1) {
			names = append(names, m[1])
		}
	}
	sort.Strings(names)
	names = dedupe(names)
	if len(names) == 0 {
		t.Fatal("no test functions found in the listed files; the pattern no longer matches how they are declared")
	}

	want := "^(" + strings.Join(names, "|") + ")$"
	got := strings.TrimSpace(strings.Join(readLines(t, filepath.Join("..", "lib", "secrets-tests.regex")), ""))
	if got != want {
		t.Fatalf("integration-tests/lib/secrets-tests.regex is stale: `make integration-secrets-only` would skip or over-run tests.\n\nRegenerate it with:\n  printf '%%s\\n' '%s' > integration-tests/lib/secrets-tests.regex\n", want)
	}

	// And it must actually be anchored. An unanchored alternation matches any
	// test whose name merely CONTAINS one of these, which is how the fuzzy
	// version swept in unrelated cases.
	if !strings.HasPrefix(got, "^(") || !strings.HasSuffix(got, ")$") {
		t.Fatalf("the filter is not anchored: %q", got)
	}
}

// Every file that declares a security use case must be listed. A new group
// file that nobody adds here is a group that `integration-secrets-only`
// silently never runs.
func TestSecretsTestFileListIsComplete(t *testing.T) {
	listed := map[string]bool{}
	for _, f := range readLines(t, filepath.Join("..", "lib", "secrets-test-files.txt")) {
		listed[f] = true
	}

	// A security test is one that claims a use case numbered UC-110 or above.
	// That is the definition the registry already uses, so it cannot drift
	// from a naming convention.
	claimRe := regexp.MustCompile(`harness\.Require\(\s*t\s*,\s*\w+\s*,\s*"UC-(\d+)b?"`)
	entries, err := os.ReadDir(filepath.Join("..", "suite"))
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") || listed[e.Name()] {
			continue
		}
		b, err := os.ReadFile(filepath.Join("..", "suite", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range claimRe.FindAllStringSubmatch(string(b), -1) {
			if n := atoiSafe(m[1]); n >= 110 {
				missing = append(missing, e.Name()+" (claims UC-"+m[1]+")")
				break
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("these files declare security use cases but are not in integration-tests/lib/secrets-test-files.txt, so `make integration-secrets-only` never runs them: %s",
			strings.Join(missing, ", "))
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func dedupe(in []string) []string {
	out := in[:0:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
