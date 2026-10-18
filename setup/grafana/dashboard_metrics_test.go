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

// TestIdentityRowMetricsAreRegistered keeps the "Identity and access" row of
// the D9 dashboard (plans/identity-and-access.md §5.15) real past the
// fixture: every aerolvm_* name its panels query must be registered in the
// Go tree, as the string literal an expvar.New*/Publish call names. A metric
// renamed or removed in code fails here, not on an empty production panel.
func TestIdentityRowMetricsAreRegistered(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "setup", "grafana", "d9-security-isolation.json"))
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
			inRow = p.Title == "Identity and access"
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
		t.Fatal(`d9-security-isolation.json has no "Identity and access" row with panels; the check would pass vacuously`)
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
		t.Fatalf("Identity and access panels query metrics no Go file registers:\n%s", strings.Join(missing, "\n"))
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
