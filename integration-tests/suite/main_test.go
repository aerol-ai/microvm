//go:build integration

// Package suite holds the live integration tests. The `integration` build tag
// keeps it out of the default `go test ./...` / `make test` run — these tests
// require a provisioned deployment (AEROL_BASE_URL + AEROL_PAT + AEROL_CAPS)
// and will skip/fail without one. Run via:
//
//	go test -tags=integration -json ./integration-tests/suite/...
package suite

import (
	"fmt"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// sc is the scenario under test, loaded once from the environment.
var sc *harness.Scenario

func TestMain(m *testing.M) {
	loaded, err := harness.LoadScenario()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration suite: %v\n", err)
		// Exit non-zero: a misconfigured run must fail loudly, not silently
		// pass by testing nothing.
		os.Exit(2)
	}
	sc = loaded
	os.Exit(m.Run())
}

// client builds a fresh SDK client wrapper for a test.
func client(t *testing.T) *harness.Client { return harness.NewClient(t, sc) }
