package catalogue

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

func TestRenderCatalogueMarkdown(t *testing.T) {
	doc := Document{
		Scenario: "test-scenario",
		Entries: []Entry{{
			ID: "SVC-01", Question: "Postgres boots", Category: "Real long-running services",
			Scenario: "test-scenario", Success: true, Runtime: "containerd",
		}},
	}
	doc.Summary = Summarize(doc.Entries)
	md := RenderMarkdown("test-scenario", doc)
	if !contains(md, "Benchmark catalogue") || !contains(md, "SVC-01") {
		t.Fatalf("unexpected markdown: %s", md)
	}
}

func TestCatalogueRegistryMatchesPlan(t *testing.T) {
	const approx = 287
	n := len(harness.CatalogueRegistry)
	if n < approx || n > approx+15 {
		t.Fatalf("catalogue registry = %d, want ≈%d", n, approx)
	}
	seen := map[string]bool{}
	for _, row := range harness.CatalogueRegistry {
		if seen[row.ID] {
			t.Fatalf("duplicate id %s", row.ID)
		}
		seen[row.ID] = true
		if row.UCRef != "" {
			if _, ok := harness.Lookup(row.UCRef); !ok {
				t.Fatalf("%s: unknown UCRef %s", row.ID, row.UCRef)
			}
		}
	}
	expanded := len(harness.ExpandedEntries(harness.CatalogueRegistry))
	if expanded < n {
		t.Fatalf("expanded %d < registry %d", expanded, n)
	}
}

func TestGenFromFixtureJSON(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "catalogue.json")
	raw := `{"scenario":"single-node","generated_at":"2026-01-01T00:00:00Z","entries":[{"id":"PROV-01","question":"cluster?","category":"Provisioning & control plane","scenario":"single-node","success":true}],"summary":{"total":1,"passed":1,"by_category":{"Provisioning & control plane":1}}}`
	if err := os.WriteFile(in, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	var doc Document
	rawRead, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawRead, &doc); err != nil {
		t.Fatal(err)
	}
	md := RenderMarkdown("single-node", doc)
	if !contains(md, "PROV-01") {
		t.Fatalf("md missing row: %s", md)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
