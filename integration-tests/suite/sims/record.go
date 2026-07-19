//go:build integration

package sims

import (
	"os"

	cat "github.com/aerol-ai/microvm/integration-tests/catalogue"
)

// PushHeartbeat emits a sim heartbeat when AEROL_PUSHGATEWAY_URL is set.
func PushHeartbeat(simID string) error {
	return cat.PushSimHeartbeat(simID)
}

// RecordResults merges sim results into the catalogue JSON artifact.
func RecordResults(scenario string, results []Result) error {
	path := CatalogueOutPath(scenario)
	entries := make([]cat.Entry, 0, len(results))
	for _, r := range results {
		e := cat.Entry{
			ID:          firstNonEmpty(r.CatalogueID, r.SimID),
			Question:    r.Question,
			Category:    r.Category,
			Subcategory: r.Subcategory,
			Runtime:     r.Runtime,
			Scenario:    scenario,
			LatencyMS:   r.LatencyMS,
			Success:     r.Success,
			Skipped:     r.Skipped,
			PublicURL:   r.PublicURL,
			Notes:       firstNonEmpty(r.SkipReason, r.Notes),
			SimID:       r.SimID,
		}
		if r.Skipped {
			e.Success = false
		}
		entries = append(entries, e)
	}
	return cat.AtomicMergeJSON(path, func(existing []byte) ([]byte, error) {
		return cat.MergeEntriesDocument(existing, scenario, entries)
	})
}

func firstNonEmpty(parts ...string) string {
	for _, p := range parts {
		if p != "" {
			return p
		}
	}
	return ""
}

// ExternalCredsPresent reports whether optional external sim deps are configured.
func ExternalCredsPresent(key string) bool {
	return os.Getenv(key) != ""
}
