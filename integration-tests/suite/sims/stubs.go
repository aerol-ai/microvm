//go:build integration

package sims

import (
	"os"
	"strings"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

func stubSims() []Sim {
	var out []Sim
	for _, row := range harness.CatalogueRegistry {
		if harness.SimIDForCatalogue(row.ID) != "" {
			continue
		}
		if !isStubCatalogueRow(row) {
			continue
		}
		row := row
		out = append(out, Sim{
			ID:           "stub-" + strings.ToLower(row.ID),
			Title:        row.Question,
			CatalogueIDs: []string{row.ID},
			Runtime:      string(firstRuntime(row)),
			Category:     row.Category,
			Subcategory:  row.Subcategory,
			Stub:         true,
			Run: func(ctx *RunContext) Result {
				return stubResult(ctx, row)
			},
		})
	}
	return out
}

func isStubCatalogueRow(row harness.CatalogueRow) bool {
	switch row.Category {
	case "Real long-running services", "Heavy compute & data", "AI agents",
		"Serverless & lifecycle automation":
		return true
	case "Isolation & untrusted code":
		return strings.HasPrefix(row.ID, "ISO-")
	default:
		return false
	}
}

func firstRuntime(row harness.CatalogueRow) harness.Runtime {
	if len(row.Runtimes) > 0 {
		return row.Runtimes[0]
	}
	return harness.RTContainerd
}

func stubResult(ctx *RunContext, row harness.CatalogueRow) Result {
	res := Result{
		SimID:       "stub-" + strings.ToLower(row.ID),
		CatalogueID: row.ID,
		Question:    row.Question,
		Category:    row.Category,
		Subcategory: row.Subcategory,
		Runtime:     string(firstRuntime(row)),
	}
	if gatedExternal(row) {
		return skip(res, "external dependency not configured")
	}
	if selected := os.Getenv("AEROL_SIMS_SELECT"); selected != "" && selected != "all" {
		if !strings.Contains(selected, res.SimID) && !strings.Contains(selected, row.ID) {
			return skip(res, "not in AEROL_SIMS_SELECT")
		}
	}
	res.Skipped = true
	res.SkipReason = "stub: not implemented in priority subset"
	return res
}

func gatedExternal(row harness.CatalogueRow) bool {
	switch row.ID {
	case "COMP-03":
		return !ExternalCredsPresent("KAGGLE_USERNAME") || !ExternalCredsPresent("KAGGLE_KEY")
	case "SVC-11", "COMP-04":
		return !ExternalCredsPresent("AEROL_SIM_DUCKDB_FIXTURE")
	default:
		return false
	}
}
