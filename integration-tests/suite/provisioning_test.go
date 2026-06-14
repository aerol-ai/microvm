//go:build integration

package suite

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// UC-10 — auth enforced: a request without a PAT must be rejected (401).
func TestAuthEnforced(t *testing.T) {
	harness.Require(t, sc, "UC-10")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sc.BaseURL+"/v1/capacity", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	// Deliberately no Authorization header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /v1/capacity without PAT: status %d, want 401", resp.StatusCode)
	}
}
