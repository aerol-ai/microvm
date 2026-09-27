package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The coverage matrix is T18's deliverable, so it has to be readable and it
// has to be honest.
//
// One column per SCENARIO, not per file: bench and catalogue runs write
// their own <scenario>-bench.json / -catalogue.json but record the same
// rep.Scenario, and cell is keyed by that name. Every extra file therefore
// added an identical duplicate column — the real matrix had eight
// cluster-3-mixed-docker columns showing the same values.
func TestWriteIndexEmitsOneColumnPerScenario(t *testing.T) {
	dir := t.TempDir()
	write := func(name, scenario string, results []Result) {
		raw, err := json.Marshal(Report{Scenario: scenario, Results: results})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Same scenario, three files — the shape that produced the duplicates.
	write("alpha.json", "alpha", []Result{{ID: "UC-01", Title: "one", Status: StatusPass}})
	write("alpha-bench.json", "alpha", []Result{{ID: "UC-01", Title: "one", Status: StatusPass}})
	write("alpha-catalogue.json", "alpha", []Result{{ID: "UC-01", Title: "one", Status: StatusPass}})
	write("beta.json", "beta", []Result{{ID: "UC-01", Title: "one", Status: StatusFail}})

	if err := writeIndex(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "index.md"))
	if err != nil {
		t.Fatal(err)
	}
	var header string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "| UC | Title |") {
			header = line
			break
		}
	}
	if header == "" {
		t.Fatal("no header row in index.md")
	}
	if got := strings.Count(header, " alpha |"); got != 1 {
		t.Errorf("header has %d alpha columns, want 1 — one column per scenario, not per report file:\n%s", got, header)
	}
	if got := strings.Count(header, " beta |"); got != 1 {
		t.Errorf("header has %d beta columns, want 1", got)
	}
}
