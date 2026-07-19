//go:build integration

package sims

import (
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// UC-108 — each simulation records its own pass/fail/skip; never a single
// all-green rollup. Failures name the sim IDs that did not succeed.
func TestSimulationsRecorded(t *testing.T) {
	if sc == nil {
		t.Skip("no scenario loaded (set AEROL_CAPS for live sims)")
	}
	RequireSimsEnabled(t, sc)
	c := harness.NewClient(t, sc)
	results := RunAll(&RunContext{T: t, Scenario: sc, Client: c})
	if err := RecordResults(sc.Name, results); err != nil {
		t.Logf("catalogue artifact: %v", err)
	}
	var failed []string
	for _, r := range results {
		t.Logf("sim %s catalogue=%s success=%v skipped=%v notes=%s", r.SimID, r.CatalogueID, r.Success, r.Skipped, firstNonEmpty(r.SkipReason, r.Notes))
		if r.Skipped {
			continue
		}
		if !r.Success {
			failed = append(failed, r.SimID)
		}
	}
	if len(failed) > 0 {
		t.Fatalf("UC-108: %d simulation(s) failed: %v", len(failed), failed)
	}
}

func TestRegistryHasRealAndStubSims(t *testing.T) {
	var real, stub int
	for _, s := range Registry {
		if s.Stub {
			stub++
		} else {
			real++
		}
	}
	if real < 11 {
		t.Fatalf("real sims = %d, want >= 11", real)
	}
	if stub == 0 {
		t.Fatal("expected stub sims for non-priority catalogue rows")
	}
}
