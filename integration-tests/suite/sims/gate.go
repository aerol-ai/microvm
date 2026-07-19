//go:build integration

package sims

import (
	"fmt"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

var sc *harness.Scenario

// LoadScenarioFromEnv is called from TestMain.
func LoadScenarioFromEnv() (*harness.Scenario, error) {
	return harness.LoadScenario()
}

// RequireSimsEnabled gates on CapSimulations + AEROL_SIMS=1 (mirrors AEROL_BENCH).
func RequireSimsEnabled(t *testing.T, scenario *harness.Scenario) {
	t.Helper()
	harness.Require(t, scenario, "UC-108")
	if os.Getenv("AEROL_SIMS") != "1" {
		t.Skip("simulations disabled: set AEROL_SIMS=1 to run UC-108 (slow; exposes services)")
	}
}

// SimsEnabled reports whether sims would run (cap + env).
func SimsEnabled(scenario *harness.Scenario) bool {
	uc, ok := harness.Lookup("UC-108")
	if !ok || !scenario.Satisfies(uc) {
		return false
	}
	return os.Getenv("AEROL_SIMS") == "1"
}

// LeasedDomain returns the scenario domain for parameterizing external URLs.
func LeasedDomain(scenario *harness.Scenario) string {
	if scenario.Domain != "" {
		return scenario.Domain
	}
	return os.Getenv("AEROL_DOMAIN")
}

// CatalogueOutPath is the JSON artifact path (AEROL_CATALOGUE_OUT).
func CatalogueOutPath(scenario string) string {
	if p := os.Getenv("AEROL_CATALOGUE_OUT"); p != "" {
		return p
	}
	return fmt.Sprintf("integration-tests/reports/%s-catalogue.json", scenario)
}
