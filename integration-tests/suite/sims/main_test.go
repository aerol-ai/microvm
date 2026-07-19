//go:build integration

package sims

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	loaded, err := LoadScenarioFromEnv()
	if err != nil {
		// Offline unit checks (registry shape) must still run under
		// -tags=integration without a provisioned cluster. Live tests
		// that need sc skip when it is nil.
		if os.Getenv("AEROL_CAPS") == "" {
			fmt.Fprintf(os.Stderr, "sims: no AEROL_CAPS — live sims will skip (%v)\n", err)
			sc = nil
			os.Exit(m.Run())
		}
		fmt.Fprintf(os.Stderr, "sims: %v\n", err)
		os.Exit(2)
	}
	sc = loaded
	os.Exit(m.Run())
}
