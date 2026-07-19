package catalogue

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// RenderMarkdown builds the investor catalogue report grouped by category.
func RenderMarkdown(scenario string, doc Document) string {
	SortEntries(doc.Entries)
	byCat := map[string][]Entry{}
	for _, e := range doc.Entries {
		byCat[e.Category] = append(byCat[e.Category], e)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Benchmark catalogue — %s\n\n", scenario)
	s := doc.Summary
	fmt.Fprintf(&b, "passed %d · failed %d · skipped %d · total %d\n\n", s.Passed, s.Failed, s.Skipped, s.Total)
	for _, cat := range harness.CatalogueCategoryOrder() {
		rows := byCat[cat]
		if len(rows) == 0 {
			continue
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Subcategory != rows[j].Subcategory {
				return rows[i].Subcategory < rows[j].Subcategory
			}
			return rows[i].ID < rows[j].ID
		})
		fmt.Fprintf(&b, "## %s\n\n", cat)
		b.WriteString("| ID | Question | Runtime | Status | Latency | Signal/Notes |\n")
		b.WriteString("|----|----------|---------|--------|---------|-------------|\n")
		for _, e := range rows {
			st := statusIcon(e)
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %dms | %s |\n",
				e.ID, mdCell(e.Question), e.Runtime, st, e.LatencyMS, mdCell(firstNonEmptyStr(e.Notes, noteFromRegistry(e.ID))))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func statusIcon(e Entry) string {
	if e.Skipped {
		return "⚪ skip"
	}
	if e.Success {
		return "✅ pass"
	}
	return "❌ fail"
}

func noteFromRegistry(id string) string {
	for _, row := range harness.CatalogueRegistry {
		if row.ID == id {
			return row.SignalDesc
		}
	}
	return ""
}

func firstNonEmptyStr(parts ...string) string {
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			return p
		}
	}
	return ""
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	const max = 120
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return s
}
