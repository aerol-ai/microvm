//go:build integration

package suite

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// Facade-convergence shared helpers (UC-233..UC-262). These UCs are the first
// live coverage of the Daytona / E2B / Runloop facades and the new v1 snapshot
// catalogue surface, so they often need headers the SDK-shaped harness helpers
// do not set (Idempotency-Key, facade org ids) and sometimes a request against
// a specific node's loopback daemon (home-node routing). fcDo is the minimal
// authenticated request primitive for that.

// fcDo issues an authenticated request against baseURL (empty → the scenario's
// ingress) with optional extra headers, returning the status and raw body. It
// never treats a non-2xx as fatal — the caller asserts on the status.
func fcDo(t *testing.T, ctx context.Context, method, baseURL, path string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	if baseURL == "" {
		baseURL = sc.BaseURL
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(baseURL, "/")+path, rdr)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+sc.PAT)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// fcSnapshotName returns a deployment-unique, lowercase snapshot name (never the
// reserved aerolvm-snapshot/ prefix).
func fcSnapshotName(t *testing.T, label string) string {
	return "uc-snap-" + label + "-" + harness.UniqueName(sc, t)
}

// fcDecode unmarshals a response body, failing with the body text on error.
func fcDecode(t *testing.T, body []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, string(body))
	}
}

// ownerAPI returns a local address that reaches sandboxd on the node that OWNS
// sandboxID. It is the complement of nonOwnerAPI. A committed snapshot's row
// lives only on its home (owner) node — snapshot rows are not replicated through
// the FSM, and cluster-wide snapshot-list aggregation is a deferred feature — so
// a facade list that must observe a committed snapshot has to be read on its
// owner. (Get/delete by name/id still route cluster-wide via the home-node
// index; only list does not aggregate yet.)
func ownerAPI(t *testing.T, c *harness.Client, sandboxID string) string {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	owner := resolvePlacementOwner(t, c, sandboxID)
	if owner == "" {
		t.Fatal("no placement owner recorded for the sandbox")
	}
	for _, n := range targets.Nodes {
		if _, ok := harness.SSHTarget(n); !ok {
			continue
		}
		if heteroNodeID(t, c, targets, n.Name) == owner {
			return "http://" + harness.SSHForward(t, n, "127.0.0.1:21212")
		}
	}
	t.Skipf("owner node %s not SSH-reachable", owner)
	return ""
}
