//go:build integration

package suite

// Group H, disruptive half — UC-155. Removes a member from the cluster.

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// UC-155 — a removed peer is revoked. After draining and removing a node, its
// client certificate must no longer be accepted.
//
// Removal that leaves the certificate working is removal in name only: the
// machine is out of the member list and still able to pull sealed material
// from every peer. This is the case that decides whether decommissioning a
// node actually reduces the blast radius.
func TestRemovedPeerCertificateIsRevoked(t *testing.T) {
	harness.Require(t, sc, "UC-155")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this removes a member from the cluster")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	victim, ok := pickNonSeedNode(targets)
	if !ok {
		t.Skip("no SSH-reachable non-seed node to remove")
	}
	victimID := heteroNodeID(t, c, targets, victim.Name)

	// Sanity: its certificate works NOW. Without this, a post-removal refusal
	// could just mean the probe was wrong all along.
	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC155_TOKEN": secretValue(t, "155")},
	})
	if probe := harness.ProbePeerSecret(t, victim, sb.ID); probe.Err != nil {
		t.Fatalf("control probe from %s before removal: %v", victim.Name, probe.Err)
	} else if probe.Status == 401 || probe.Status == 403 {
		t.Fatalf("%s's own certificate was already refused (%d) before removal; this case cannot tell revocation from a broken probe", victim.Name, probe.Status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rejoined := false
	t.Cleanup(func() {
		if rejoined {
			return
		}
		// Removing a member is the most invasive thing in this suite. Put it
		// back: every later cluster case runs against a smaller fleet
		// otherwise, and the report would blame whatever ran next.
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer ccancel()
		if err := c.PostJSON(cctx, "/v1/cluster/nodes/"+victimID+"/uncordon", nil, nil); err != nil {
			t.Errorf("RESTORE: uncordon %s: %v", victimID, err)
		}
		target, _ := harness.SSHTarget(victim)
		if out, err := harness.SSHRun(t, target, "sudo systemctl restart sandboxd"); err != nil {
			t.Errorf("RESTORE FAILED: %s was removed from the cluster and could not be restarted; the rest of this run is against a smaller fleet: %v\n%s",
				victim.Name, err, out)
		}
	})

	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+victimID+"/drain", nil, nil); err != nil {
		t.Fatalf("drain %s: %v", victimID, err)
	}
	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+victimID+"/remove", nil, nil); err != nil {
		// Not every build exposes a remove verb; say so rather than assert
		// revocation of a member that was never removed.
		t.Skipf("no cluster remove verb for %s (%v); UC-155 cannot inject its fault here", victimID, err)
	}

	// Replay the removed node's own certificate. It must stop working.
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		probe := harness.ProbePeerSecret(t, victim, sb.ID)
		if probe.Err == nil && (probe.Status == 401 || probe.Status == 403) {
			t.Logf("UC-155 PASS: the removed peer's certificate is refused (%d)", probe.Status)
			return
		}
		if probe.Err == nil && probe.Status == 0 {
			t.Logf("UC-155 PASS: the removed peer can no longer establish a peer connection at all")
			return
		}
		time.Sleep(15 * time.Second)
	}

	final := harness.ProbePeerSecret(t, victim, sb.ID)
	t.Fatalf("a REMOVED node's certificate still reaches the peer API (status %d, err %v): removal did not reduce the blast radius at all — the machine is out of the member list and can still pull sealed material",
		final.Status, final.Err)
}
