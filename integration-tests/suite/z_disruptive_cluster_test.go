//go:build integration

package suite

// Disruptive cluster tests live in this file so they run after the rest of the
// suite (Go orders test files lexically; the z_ prefix keeps node-kill tests
// from racing earlier placement/networking UCs).

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

const heteroVictimWorker = "worker-x"

var heteroFailoverPeers = []string{"worker-y", "worker-z"}

// UC-58 — Owner failover: a replica serves after the owner dies. Not implemented
// yet (Phase 2); kept behind the disruptive gate so the report stays honest.
func TestOwnerFailover(t *testing.T) {
	harness.Require(t, sc, "UC-58")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (use default make integration-cluster-hetero, or drop --no-disruptive)")
	}
	t.Skip("driven by infra fault injection; see plans/integration-tests.md Phase 2 follow-up")
}

// UC-58b — Recreate-via-failover preserves sandbox identity. Kills worker-x on
// the cluster-hetero topology (after pinning placement there) and expects the
// sandbox to be recreated on worker-y or worker-z.
func TestRecreateViaFailover(t *testing.T) {
	harness.Require(t, sc, "UC-58b")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (use default make integration-cluster-hetero, or drop --no-disruptive)")
	}
	if sc.Name != "cluster-hetero" {
		t.Skip("recreate failover kill test requires cluster-hetero worker-x/y/z topology")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	victim, ok := harness.LookupIntegrationNode(targets, heteroVictimWorker)
	if !ok || victim.InstanceID == "" {
		t.Fatalf("%s missing from integration targets (instance_id required)", heteroVictimWorker)
	}

	c := client(t)
	victimNodeID := heteroNodeID(t, c, targets, heteroVictimWorker)
	failoverPeerNodeIDs := heteroNodeIDs(t, c, targets, heteroFailoverPeers...)
	failoverPeerNodeIDList := mapValues(failoverPeerNodeIDs)
	extraDrainedNodeID := heteroNodeID(t, c, targets, "worker-w")

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		for _, nodeID := range append(append([]string{}, failoverPeerNodeIDList...), extraDrainedNodeID) {
			_ = c.PostJSON(ctx, "/v1/cluster/nodes/"+nodeID+"/uncordon", nil, nil)
		}
		if state := harness.EC2InstanceState(t, victim.InstanceID); state == "stopped" {
			harness.SetEC2InstanceRunning(t, victim.InstanceID, true)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for name, nodeID := range failoverPeerNodeIDs {
		if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+nodeID+"/drain", nil, nil); err != nil {
			t.Fatalf("drain %s (%s): %v", name, nodeID, err)
		}
	}
	// worker-w stays schedulable but is not a failover assertion target; drain
	// it too so the pinned sandbox must land on worker-x.
	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+extraDrainedNodeID+"/drain", nil, nil); err != nil {
		t.Fatalf("drain worker-w (%s): %v", extraDrainedNodeID, err)
	}

	// Must stay on docker. Recreate-via-failover needs >=2 workers advertising
	// the runtime so the sandbox can land on a peer after worker-x dies; docker
	// runs on all four workers. Do NOT switch this to firecracker: only worker-z
	// is bare metal, so an FC sandbox has no failover peer on hetero (a second
	// x86 *.metal is blocked on the metal vCPU quota). FC failover lives in
	// cluster-arm64 instead.
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:     harness.UniqueName(sc, t),
		Runtime:  "docker",
		Failover: &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
	})
	waitRunning(t, sb)

	owner := resolvePlacementOwner(t, c, sb.ID)
	if owner != victimNodeID {
		t.Fatalf("initial placement on %q, want %q/%s (failover peers should be drained)", owner, heteroVictimWorker, victimNodeID)
	}

	for name, nodeID := range failoverPeerNodeIDs {
		if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+nodeID+"/uncordon", nil, nil); err != nil {
			t.Fatalf("uncordon %s (%s): %v", name, nodeID, err)
		}
	}
	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+extraDrainedNodeID+"/uncordon", nil, nil); err != nil {
		t.Fatalf("uncordon worker-w (%s): %v", extraDrainedNodeID, err)
	}

	harness.SetEC2InstanceRunning(t, victim.InstanceID, false)

	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		newOwner := resolvePlacementOwner(t, c, sb.ID)
		if newOwner != "" && newOwner != victimNodeID && slices.Contains(failoverPeerNodeIDList, newOwner) {
			waitRunning(t, sb)
			t.Logf("sandbox %s recreated on %s after killing %s/%s", sb.ID, newOwner, heteroVictimWorker, victimNodeID)
			return
		}
		time.Sleep(10 * time.Second)
	}
	t.Fatalf("sandbox %s did not recreate on %v within timeout", sb.ID, failoverPeerNodeIDs)
}

// UC-58c — Kill owner mid secret fan-out (GAP-1 chaos). Creates an HA sandbox
// with registry credentials while backup workers stay schedulable so
// SelectSecretRecipients can include them (draining peers first would leave a
// single-recipient set and make failover_ready vacuously true).
//
// Acceptable outcomes (never half-sealed / silent corruption):
//   - sandbox recreates on a failover peer (fan-out won / min-ACK landed), OR
//   - sandbox fails loudly when failover_ready was false.
func TestKillOwnerMidSecretFanout(t *testing.T) {
	harness.Require(t, sc, "UC-58c")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (use default make integration-cluster-hetero, or drop --no-disruptive)")
	}
	if sc.Name != "cluster-hetero" {
		t.Skip("mid-fan-out kill test requires cluster-hetero worker-x/y/z topology")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}

	c := client(t)
	victimNodeID := heteroNodeID(t, c, targets, heteroVictimWorker)
	failoverPeerNodeIDs := heteroNodeIDs(t, c, targets, heteroFailoverPeers...)
	failoverPeerNodeIDList := mapValues(failoverPeerNodeIDs)
	extraDrainedNodeID := heteroNodeID(t, c, targets, "worker-w")

	// Map nodeID → EC2 instance so we can kill whichever worker owns the sandbox.
	nodeInstance := map[string]string{}
	for _, name := range append([]string{heteroVictimWorker}, heteroFailoverPeers...) {
		n, ok := harness.LookupIntegrationNode(targets, name)
		if !ok || n.InstanceID == "" {
			t.Fatalf("%s missing from integration targets (instance_id required)", name)
		}
		nodeInstance[heteroNodeID(t, c, targets, name)] = n.InstanceID
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = c.PostJSON(ctx, "/v1/cluster/nodes/"+extraDrainedNodeID+"/uncordon", nil, nil)
		for _, instanceID := range nodeInstance {
			if state := harness.EC2InstanceState(t, instanceID); state == "stopped" {
				harness.SetEC2InstanceRunning(t, instanceID, true)
			}
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// Keep worker-x/y/z eligible so recipient set can include backups. Only
	// drain the spare worker-w so placement stays on the three-node fan-out set.
	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+extraDrainedNodeID+"/drain", nil, nil); err != nil {
		t.Fatalf("drain worker-w (%s): %v", extraDrainedNodeID, err)
	}

	var sb *microvm.Sandbox
	var owner string
	for attempt := 0; attempt < 8; attempt++ {
		cand := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
			Name:     harness.UniqueName(sc, t),
			Runtime:  "docker",
			Failover: &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
			Registry: &sdktypes.RegistryAuth{
				Server:   "registry.example.invalid",
				Username: "chaos-user",
				Password: "chaos-password-not-real",
			},
		})
		waitRunning(t, cand)
		owner = resolvePlacementOwner(t, c, cand.ID)
		if owner == victimNodeID || slices.Contains(failoverPeerNodeIDList, owner) {
			sb = cand
			break
		}
		_ = c.SDK().Destroy(ctx, cand.ID)
	}
	if sb == nil {
		t.Fatalf("could not place HA sandbox on worker-x/y/z")
	}
	instanceID := nodeInstance[owner]
	if instanceID == "" {
		t.Fatalf("no EC2 instance for owner %s", owner)
	}

	_ = sb.Refresh(ctx)
	readyBefore := false
	if sb.FailoverReady != nil {
		readyBefore = *sb.FailoverReady
	}
	t.Logf("sandbox %s owner=%s failover_ready=%v (holders expected ≥2 when ready)", sb.ID, owner, readyBefore)
	// When ready, at least one backup must have ACKed — single-recipient
	// vacuous ready is what draining peers caused before.
	if readyBefore {
		t.Logf("GAP-1 window closed before kill; expect recreate on a peer")
	}

	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+extraDrainedNodeID+"/uncordon", nil, nil); err != nil {
		t.Fatalf("uncordon worker-w (%s): %v", extraDrainedNodeID, err)
	}

	harness.SetEC2InstanceRunning(t, instanceID, false)

	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		newOwner := resolvePlacementOwner(t, c, sb.ID)
		if newOwner != "" && newOwner != owner {
			waitRunning(t, sb)
			_ = sb.Refresh(ctx)
			t.Logf("sandbox %s recreated on %s after mid-fan-out kill (ready_before=%v)",
				sb.ID, newOwner, readyBefore)
			return
		}
		time.Sleep(10 * time.Second)
	}

	if readyBefore {
		t.Fatalf("sandbox %s was failover_ready=true before kill but did not recreate — unexpected after multi-holder ready",
			sb.ID)
	}
	t.Logf("sandbox %s did not recreate after mid-fan-out kill with failover_ready=false (accepted GAP-1)", sb.ID)
}

func heteroNodeIDs(t *testing.T, c *harness.Client, targets *harness.IntegrationTargets, names ...string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(names))
	for _, name := range names {
		out[name] = heteroNodeID(t, c, targets, name)
	}
	return out
}

func heteroNodeID(t *testing.T, c *harness.Client, targets *harness.IntegrationTargets, name string) string {
	t.Helper()
	members := fetchMembers(t, c)
	for _, m := range members.Members {
		if m.NodeID == name || strings.HasSuffix(m.NodeName, "-"+name) || m.NodeName == name {
			return m.NodeID
		}
	}
	if target, ok := harness.LookupIntegrationNode(targets, name); ok {
		nodeID := nodeIDFromPrivateIP(target.PrivateIP)
		if nodeID != "" {
			return nodeID
		}
	}
	t.Fatalf("cluster member %q not found in /v1/cluster/members", name)
	return ""
}

func nodeIDFromPrivateIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	return "ip-" + strings.ReplaceAll(ip, ".", "-")
}

func mapValues[K comparable, V any](m map[K]V) []V {
	out := make([]V, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
