package grafana_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// Guard against dashboard drift: every aerolvm_* name referenced in Grafana
// JSON must exist in the committed /v1/metrics fixture.
func TestDashboardMetricsExistInFixture(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	fixturePath := filepath.Join(root, "setup", "grafana", "fixtures", "known_metrics.txt")
	known, err := loadMetricFixture(fixturePath)
	if err != nil {
		t.Fatal(err)
	}

	dashboardDir := filepath.Join(root, "setup", "grafana")
	entries, err := os.ReadDir(dashboardDir)
	if err != nil {
		t.Fatal(err)
	}

	metricRE := regexp.MustCompile(`aerolvm_[a-z0-9_]+`)
	var violations []string

	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		path := filepath.Join(dashboardDir, ent.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// Sanity: valid JSON.
		if !json.Valid(raw) {
			t.Fatalf("%s is not valid JSON", ent.Name())
		}
		for _, name := range unique(metricRE.FindAllString(string(raw), -1)) {
			if !known[name] {
				violations = append(violations, ent.Name()+": "+name)
			}
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("dashboard metrics missing from %s:\n%s", fixturePath, strings.Join(violations, "\n"))
	}
}

// TestCanAdmitIsCountedNotMinned: aerolvm_host_pressure_can_admit is 0 on
// every cluster server and gateway (they never take a sandbox; issue
// #1343), so min() or avg() of it across nodes reads 0 on any cluster that
// has one, however much room the workers have. A panel sums it (how many
// nodes can admit) or keeps to the workers.
func TestCanAdmitIsCountedNotMinned(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	minned := regexp.MustCompile(`\b(min|avg)\s*(\(\s*|by\s*\([^)]*\)\s*\(\s*)aerolvm_host_pressure_can_admit\b`)
	found := 0
	for _, dir := range []string{filepath.Join(root, "setup", "grafana"), filepath.Join(root, "charts", "aerolvm", "dashboards")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, ent.Name()))
			if err != nil {
				t.Fatal(err)
			}
			found += strings.Count(string(raw), "aerolvm_host_pressure_can_admit")
			if m := minned.FindString(string(raw)); m != "" {
				t.Errorf("%s: %q reads 0 whenever a server or gateway is scraped; sum it, or keep to the workers", ent.Name(), m)
			}
		}
	}
	if found == 0 {
		t.Fatal("no dashboard reads aerolvm_host_pressure_can_admit: the check found nothing to check")
	}
}

// TestIdentityRowMetricsAreRegistered keeps the "Identity and access" row of
// the D9 dashboard (plans/identity-and-access.md §5.15) real past the
// fixture: every aerolvm_* name its panels query must be registered in the
// Go tree, as the string literal an expvar.New*/Publish call names. A metric
// renamed or removed in code fails here, not on an empty production panel.
func TestIdentityRowMetricsAreRegistered(t *testing.T) {
	rowMetricsRegistered(t, "d9-security-isolation.json", "Identity and access")
}

// TestKeyCustodyRowMetricsAreRegistered is the same check for the "Key
// custody" row (plans/customer-key-custody.md Section 8).
func TestKeyCustodyRowMetricsAreRegistered(t *testing.T) {
	rowMetricsRegistered(t, "d9-security-isolation.json", "Key custody")
}

// TestRolloutRowMetricsAreRegistered is the same check for the D5
// "Rollouts" row (plans/kubectl-style-cluster-ops.md §10.1).
func TestRolloutRowMetricsAreRegistered(t *testing.T) {
	rowMetricsRegistered(t, "d5-cluster-health.json", "Rollouts")
}

func rowMetricsRegistered(t *testing.T, dashboard, row string) {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "setup", "grafana", dashboard))
	if err != nil {
		t.Fatal(err)
	}
	var dash struct {
		Panels []struct {
			Type    string `json:"type"`
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatal(err)
	}
	metricRE := regexp.MustCompile(`aerolvm_[a-z0-9_]+`)
	var names []string
	inRow, sawRow, panels := false, false, 0
	for _, p := range dash.Panels {
		if p.Type == "row" {
			inRow = p.Title == row
			sawRow = sawRow || inRow
			continue
		}
		if !inRow {
			continue
		}
		panels++
		for _, target := range p.Targets {
			names = append(names, metricRE.FindAllString(target.Expr, -1)...)
		}
	}
	if !sawRow || panels == 0 {
		t.Fatalf("%s has no %q row with panels; the check would pass vacuously", dashboard, row)
	}
	registered := map[string]bool{}
	literalRE := regexp.MustCompile(`"(aerolvm_[a-z0-9_]+)"`)
	for _, dir := range []string{"cmd", "internal", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range literalRE.FindAllStringSubmatch(string(src), -1) {
				registered[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var missing []string
	for _, name := range unique(names) {
		if !registered[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%s panels query metrics no Go file registers:\n%s", row, strings.Join(missing, "\n"))
	}
}

func loadMetricFixture(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	known := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		known[line] = true
	}
	return known, sc.Err()
}

func unique(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
