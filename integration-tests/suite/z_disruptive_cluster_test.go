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

// UC-58b — Recreate-via-failover preserves sandbox identity. Creates a
// recreate-policy sandbox, kills whichever node owns it, and expects it to
// reappear under the same id on a live peer.
//
// The kill is a daemon stop over SSH (the harness's daemon kill), not an EC2
// stop-instances: a graceful instance shutdown lets the node flap in gossip and
// delays SWIM dead-detection past the window, which is why the earlier
// EC2-stop version never recreated in time. The daemon stop is also the fault
// these cases model — SWIM marks the owner dead and placement reassigns — and
// leaves the box reachable for a reliable restore.
func TestRecreateViaFailover(t *testing.T) {
	harness.Require(t, sc, "UC-58b")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (use default make integration-cluster-hetero, or drop --no-disruptive)")
	}
	if sc.Name != "cluster-hetero" {
		t.Skip("recreate failover kill test requires the cluster-hetero worker topology")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}

	c := client(t)

	// Docker runs on every hetero worker, so a recreate-policy sandbox always has
	// a peer to land on after its owner dies. Do NOT switch to firecracker: only
	// worker-z is bare metal, so an FC sandbox has no FC failover peer on hetero.
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:     harness.UniqueName(sc, t),
		Runtime:  "docker",
		Failover: &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
	})
	waitRunning(t, sb)

	owner := resolvePlacementOwner(t, c, sb.ID)
	if owner == "" {
		t.Fatal("no placement owner recorded; there is nothing to kill")
	}
	victim, ok := nodeForClusterID(t, c, targets, owner)
	if !ok {
		t.Skipf("owner %s is not a node this suite can reach", owner)
	}
	requireNonSeedVictim(t, victim)

	t.Logf("killing owner %s (%s); expect recreate on a peer", owner, victim.Name)
	t.Cleanup(harness.KillNodeDaemon(t, victim))

	newOwner := awaitNewOwner(t, c, sb.ID, owner, failoverOpenTimeout)
	waitRunning(t, sb)
	t.Logf("sandbox %s recreated under the same id on %s after killing %s", sb.ID, newOwner, owner)
}

// UC-58d — A snapshot-backed sandbox survives owner failover under the per-owner
// snapshot identity. The sandbox is created FROM a registered snapshot (resolved
// by name, under the #13 (owner_ref, name) identity), given a recreate failover
// policy; whichever node owns it is killed (daemon stop), and the sandbox must
// recreate on a peer. This exercises the rebuilt snapshot tables on the cluster
// recreate path, which a fresh-provisioned run otherwise only touches on create.
//
// The snapshot is an image-registered (portable) snapshot on purpose: a
// committed, local-only snapshot is intentionally refused by recreate failover
// ("requires a portable image; local-only images cannot be recreated on another
// node"), so the snapshot-backed failover path is only reachable with a portable
// one. Whether the snapshot name stays resolvable after the home node dies is
// logged, not asserted — the catalogue is home-node-local (B6), so that is not a
// guarantee this test should pin.
func TestSnapshotBackedFailover(t *testing.T) {
	harness.Require(t, sc, "UC-58d")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (use default make integration-cluster-hetero, or drop --no-disruptive)")
	}
	if sc.Name != "cluster-hetero" {
		t.Skip("snapshot-backed failover test requires the cluster-hetero worker topology")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}

	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), failoverOpenTimeout+3*time.Minute)
	defer cancel()
	snapName := fcSnapshotName(t, "ha58d")

	// Register a PORTABLE snapshot (an external-registry image ref) so a recreate
	// sandbox is allowed to be created from it. A committed local-only snapshot
	// would be refused by the recreate portability check before failover.
	if _, err := c.SDK().RegisterSnapshot(ctx, sdktypes.RegisterSnapshotOptions{
		Name:  snapName,
		Image: "alpine:3.20",
	}); err != nil {
		t.Fatalf("RegisterSnapshot(%q): %v", snapName, err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.SDK().DeleteSnapshot(cctx, snapName)
	})

	// Create the sandbox FROM the snapshot's NAME (resolved under (owner_ref,
	// name)), with a recreate failover policy. docker runs on every hetero worker.
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:     harness.UniqueName(sc, t),
		Image:    snapName,
		Runtime:  "docker",
		Failover: &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
	})
	waitRunning(t, sb)

	owner := resolvePlacementOwner(t, c, sb.ID)
	if owner == "" {
		t.Fatal("no placement owner recorded; there is nothing to kill")
	}
	victim, ok := nodeForClusterID(t, c, targets, owner)
	if !ok {
		t.Skipf("owner %s is not a node this suite can reach", owner)
	}
	requireNonSeedVictim(t, victim)

	// Kill the owner's daemon (SWIM dead-detection; box stays up for restore).
	t.Logf("killing owner %s (%s) of snapshot-backed sandbox %s", owner, victim.Name, sb.ID)
	t.Cleanup(harness.KillNodeDaemon(t, victim))

	newOwner := awaitNewOwner(t, c, sb.ID, owner, failoverOpenTimeout)
	waitRunning(t, sb)

	// Observational only (not a guarantee this test pins): the catalogue is
	// home-node-local, so after the owner dies the name may or may not still
	// resolve from a survivor. Log whichever it is.
	if _, err := c.SDK().GetSnapshot(ctx, snapName); err != nil {
		t.Logf("note: snapshot %q not resolvable after owner death (home-node-local catalogue): %v", snapName, err)
	} else {
		t.Logf("snapshot %q still resolvable after failover", snapName)
	}
	t.Logf("snapshot-backed sandbox %s recreated under the same id on %s after killing %s", sb.ID, newOwner, owner)
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
		// NodeID carries the Terraform-assigned name on these deployments
		// (aerolvm-itest-<scenario>-node1), so the short name given here is a
		// SUFFIX of it. That match was missing, and without it every lookup
		// for "node1" fell through to the private-IP fallback below and
		// returned ip-10-42-1-46 — an id no member has. The live S2 run then
		// spent 4 minutes per WithNodeEnv call waiting for a node to "rejoin"
		// under an identity that never existed, and reported a false
		// "RESTORE FAILED ... every later case is suspect" each time.
		if m.NodeID == name || strings.HasSuffix(m.NodeID, "-"+name) ||
			m.NodeName == name || strings.HasSuffix(m.NodeName, "-"+name) {
			return m.NodeID
		}
	}
	// Fallback only: derive an id from the private IP. It is a GUESS about
	// the daemon's naming and is wrong wherever SB_NODE_ID is set explicitly,
	// so a caller comparing it against the member list will never match.
	if target, ok := harness.LookupIntegrationNode(targets, name); ok {
		nodeID := nodeIDFromPrivateIP(target.PrivateIP)
		if nodeID != "" {
			t.Logf("heteroNodeID(%q): not in /v1/cluster/members; falling back to the private-IP form %q, which may not be this node's real id", name, nodeID)
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
