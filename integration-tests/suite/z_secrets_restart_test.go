//go:build integration

package suite

// Group C, disruptive half — UC-125. Restarts every node, so it sorts after
// the rest of the suite.

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// UC-125 — a whole-cluster restart restores holder counts and does not leave
// failover_ready stuck false.
//
// This MUST run on an enterprise scenario, not merely a cluster one.
// pkg/daemon/daemon.go makes a boot re-fanout error FATAL under enterprise
// while a plain cluster only logs a warning, and seal_distribute.go errors
// whenever the authoritative placement read is unavailable — which is exactly
// the state of a cold start before quorum. On S2 this passes; on the
// enterprise posture the same code path can deadlock every worker. The
// registry therefore requires CapEnterprise.
//
// harness.WithClusterEnv with no variables is the restart: it brings the seed
// back FIRST, because rolling-restarting all three SWIM members with the seed
// last once split a live cluster 2+1 (the joiners came up with no rendezvous
// to gossip with and orphaned themselves).
func TestWholeClusterRestartRestoresHolders(t *testing.T) {
	harness.Require(t, sc, "UC-125")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this restarts every node")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC125_TOKEN": secretValue(t, "125")},
	})
	before := harness.AwaitSecretHolders(t, c, sb.ID, resealTimeout, func(v harness.SecretHoldersView) bool {
		return len(v.Holders) >= 2
	})

	harness.WithClusterEnv(t, targets, nil, func(res map[string]harness.NodeBootResult) {
		for name, r := range res {
			if !r.Started {
				// Under enterprise a fatal boot re-fanout error looks exactly
				// like this, which is the deadlock this case exists to catch.
				t.Fatalf("node %s did not come back after the cluster restart (status %q). Under enterprise a boot re-fanout error is FATAL — check the journal for the re-fanout line.\n%s",
					name, r.Status, tailLines(r.Journal, 40))
			}
		}

		after := harness.AwaitSecretHolders(t, c, sb.ID, 10*time.Minute, func(v harness.SecretHoldersView) bool {
			return len(v.Holders) >= len(before.Holders)
		})
		if len(after.Holders) < len(before.Holders) {
			t.Fatalf("holder count fell from %d to %d across a cluster restart: ReFanoutClusterSecrets did not restore the set (%v -> %v)",
				len(before.Holders), len(after.Holders), before.Holders, after.Holders)
		}
		if !after.Converged() {
			t.Fatalf("the boot re-fanout never settled: put=%v delete=%v", after.PendingPut, after.PendingDelete)
		}
		// failover_ready stuck false is the symptom an operator sees: the
		// sandbox looks un-protected forever even though every copy is there.
		harness.AwaitFailoverReady(t, c, sb.ID, 10*time.Minute)
	})
}
