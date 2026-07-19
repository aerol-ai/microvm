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
