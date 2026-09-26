//go:build integration

package suite

// Group M, UC-169 — the plaintext leak sweep.
//
// This is the only check that covers leak paths nobody thought to enumerate.
// Every other case asserts that ONE surface is clean; this one takes a canary
// and looks for it everywhere a secret could plausibly come to rest.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-169 — after a real workload, the canary appears nowhere on any node.
func TestPlaintextLeakSweep(t *testing.T) {
	harness.Require(t, sc, "UC-169")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	canary := secretValue(t, "169-canary")

	// Exercise the paths a secret travels: sealed at create, replicated to
	// peers, read back through the API, and logged about.
	sb := createSecretSandbox(t, c, map[string]string{"UC169_CANARY": canary})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for i := 0; i < 3; i++ {
		if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", nil); err != nil {
			t.Fatalf("read env: %v", err)
		}
	}
	// A failed create too: error paths are where values get interpolated
	// into messages.
	_, _ = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Name:  "UC169 invalid name with spaces",
		Image: harness.DefaultImage,
		Env:   map[string]string{"UC169_CANARY": canary},
	})
	// And let the exporter and the log writer catch up before looking.
	time.Sleep(30 * time.Second)

	swept := 0
	for _, node := range targets.Nodes {
		target, ok := harness.SSHTarget(node)
		if !ok {
			continue
		}
		swept++
		for _, form := range leakForms(canary) {
			out, err := harness.SSHRun(t, target, leakGrepScript(form.encoded))
			if err != nil {
				t.Fatalf("leak sweep on %s (%s form): %v\n%s", node.Name, form.name, err, out)
			}
			if hits := strings.TrimSpace(out); hits != "" && !strings.Contains(hits, "NOHITS") {
				// Never print the canary; print WHERE it was found.
				t.Errorf("the canary is on disk on %s in %s form. Locations:\n%s", node.Name, form.name, tailLines(hits, 20))
			}
		}
	}
	if swept == 0 {
		t.Fatal("no node was swept; this case would have passed having looked nowhere")
	}
	t.Logf("UC-169: swept %d node(s) for %d encodings of the canary", swept, len(leakForms(canary)))
}
