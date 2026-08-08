package harness

import "testing"

func TestCatalogueRegistryWellFormed(t *testing.T) {
	const want = 298 // category table sums (includes HA-07b / UC-58c)
	if len(CatalogueRegistry) != want {
		t.Fatalf("catalogue rows = %d, want %d", len(CatalogueRegistry), want)
	}
	seen := map[string]bool{}
	for _, row := range CatalogueRegistry {
		if row.ID == "" {
			t.Fatalf("empty catalogue id: %+v", row)
		}
		if seen[row.ID] {
			t.Fatalf("duplicate catalogue id %q", row.ID)
		}
		seen[row.ID] = true
		if row.UCRef != "" {
			if _, ok := Lookup(row.UCRef); !ok {
				t.Fatalf("%s: unknown UCRef %q", row.ID, row.UCRef)
			}
		}
		if row.Question == "" {
			t.Fatalf("%s: empty question", row.ID)
		}
		if row.Category == "" {
			t.Fatalf("%s: empty category", row.ID)
		}
	}
}

func TestCatalogueExpandedEntries(t *testing.T) {
	expanded := ExpandedEntries(CatalogueRegistry)
	if len(expanded) < len(CatalogueRegistry) {
		t.Fatalf("expanded %d < registry %d", len(expanded), len(CatalogueRegistry))
	}
	for _, e := range expanded {
		if e.ID == "" || e.Question == "" {
			t.Fatalf("invalid expanded entry: %+v", e)
		}
	}
}
