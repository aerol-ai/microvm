package catalogue

import "sort"

// Entry is one executed catalogue question recorded into the JSON artifact.
type Entry struct {
	ID          string `json:"id"`
	Question    string `json:"question"`
	Category    string `json:"category"`
	Subcategory string `json:"subcategory,omitempty"`
	Runtime     string `json:"runtime,omitempty"`
	Scenario    string `json:"scenario"`
	LatencyMS   int64  `json:"latency_ms,omitempty"`
	Success     bool   `json:"success"`
	Skipped     bool   `json:"skipped,omitempty"`
	PublicURL   string `json:"public_url,omitempty"`
	Artifact    string `json:"artifact,omitempty"`
	Notes       string `json:"notes,omitempty"`
	SimID       string `json:"sim_id,omitempty"`
}

// Document is the on-disk catalogue JSON shape.
type Document struct {
	Scenario    string         `json:"scenario"`
	GeneratedAt string         `json:"generated_at"`
	Entries     []Entry        `json:"entries"`
	Summary     Summary        `json:"summary"`
	Machine     map[string]any `json:"machine,omitempty"`
}

// Summary rolls up entry outcomes.
type Summary struct {
	Total      int            `json:"total"`
	Passed     int            `json:"passed"`
	Failed     int            `json:"failed"`
	Skipped    int            `json:"skipped"`
	ByCategory map[string]int `json:"by_category"`
}

// Summarize builds a summary from entries.
func Summarize(entries []Entry) Summary {
	s := Summary{ByCategory: map[string]int{}}
	for _, e := range entries {
		s.Total++
		s.ByCategory[e.Category]++
		switch {
		case e.Skipped:
			s.Skipped++
		case e.Success:
			s.Passed++
		default:
			s.Failed++
		}
	}
	return s
}

// SortEntries sorts entries by category, subcategory, id for stable output.
func SortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Category != entries[j].Category {
			return entries[i].Category < entries[j].Category
		}
		if entries[i].Subcategory != entries[j].Subcategory {
			return entries[i].Subcategory < entries[j].Subcategory
		}
		return entries[i].ID < entries[j].ID
	})
}
