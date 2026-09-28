//go:build integration

package suite

// Group J — storage retirement and fleet-scale reads (§7 group J,
// F15/F18/F19). UC-160..162.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/internal/cluster"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// storageRetirements is GET /v1/cluster/storage-retirements: the
// attestations (lasting proof a disk was destroyed) and the open
// decommission jobs (UC-160: nodes that still owe a wipe).
type storageRetirements struct {
	Retirements []struct {
		NodeID     string `json:"node_id"`
		AttestedAt string `json:"attested_at"`
		Actor      string `json:"actor"`
		Reason     string `json:"reason"`
	} `json:"retirements"`
	Obligations []cluster.StorageObligationView `json:"obligations"`
}

func (r storageRetirements) has(nodeID string) bool {
	for _, rec := range r.Retirements {
		if rec.NodeID == nodeID {
			return true
		}
	}
	return false
}

func (r storageRetirements) obligation(nodeID string) (cluster.StorageObligationView, bool) {
	for _, o := range r.Obligations {
		if o.NodeID == nodeID {
			return o, true
		}
	}
	return cluster.StorageObligationView{}, false
}

// UC-160 — draining a node that holds sealed material opens a visible
// decommission obligation; an attestation, allowed only once the node is
// gone, discharges it and stays listed as the proof.
//
// Split into the two halves the product actually allows. The old single case
// drained a LIVE worker and immediately attested it — which the server
// refuses (409) while gossip reports the node alive, correctly: a live node
// can still ACK, so attesting its disk destroyed would throw away a real
// reminder. Weakening that check to make the case pass would defeat it.
func TestDrainRaisesAStorageRetirementObligation(t *testing.T) {
	harness.Require(t, sc, "UC-160")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this stops the drained node to attest its storage")
	}
	c := client(t)
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}

	// A drained node must hold something, or the obligation has no subject.
	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC160_TOKEN": secretValue(t, "160")},
	})
	view := harness.AwaitSecretHolders(t, c, sb.ID, resealTimeout, func(v harness.SecretHoldersView) bool {
		return len(v.Holders) >= 2
	})
	owner := resolvePlacementOwner(t, c, sb.ID)
	candidates := withoutString(view.Holders, owner)
	if len(candidates) == 0 {
		t.Skipf("holder set %v is owner-only; nothing to retire", view.Holders)
	}
	victim := candidates[0]
	victimNode, ok := nodeForClusterID(t, c, targets, victim)
	if !ok {
		t.Skipf("holder %s is not an SSH-reachable node this suite can stop", victim)
	}
	requireNonSeedVictim(t, victimNode)

	list := func() storageRetirements {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var recs storageRetirements
		if err := c.GetJSON(ctx, "/v1/cluster/storage-retirements", &recs); err != nil {
			t.Fatalf("list storage retirements: %v", err)
		}
		return recs
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// LIFO: revoke the attestation, then bring the node back (waiting for
	// the rejoin), then uncordon — so no later case inherits a drained node
	// or an attestation claiming a live disk is clean.
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer ccancel()
		if err := c.PostJSON(cctx, "/v1/cluster/nodes/"+victim+"/uncordon", nil, nil); err != nil {
			t.Errorf("RESTORE FAILED: node %s left drained: %v", victim, err)
		}
	})
	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+victim+"/drain", nil, nil); err != nil {
		t.Fatalf("drain %s: %v", victim, err)
	}

	// Half 1: the job appears, from the list alone.
	var job cluster.StorageObligationView
	deadline := time.Now().Add(2 * time.Minute)
	opened := false
	for time.Now().Before(deadline) {
		if o, ok := list().obligation(victim); ok {
			job, opened = o, true
			break
		}
		time.Sleep(10 * time.Second)
	}
	if !opened {
		t.Fatalf("draining %s, which holds a sealed copy, opened no storage-retirement obligation: the node could leave the fleet with sealed material on its disk and nothing recording that it must be destroyed", victim)
	}
	if job.Holders == 0 && job.PendingDeletes == 0 {
		t.Fatalf("the obligation for %s shows neither a held copy nor a pending delete: %+v", victim, job)
	}
	t.Logf("UC-160: obligation opened for %s: holders=%d pending=%d complete=%v stale=%d", victim, job.Holders, job.PendingDeletes, job.Complete, len(job.StaleReporters))

	// Half 2: stop the node; the attestation is refused while gossip still
	// reports it alive, and accepted once it is gone.
	t.Cleanup(harness.KillNodeDaemon(t, victimNode))
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.Delete(cctx, "/v1/cluster/nodes/"+victim+"/storage-retired")
	})
	attested := false
	var lastErr error
	deadline = time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		actx, acancel := context.WithTimeout(context.Background(), 30*time.Second)
		lastErr = c.PostJSON(actx, "/v1/cluster/nodes/"+victim+"/storage-retired", map[string]any{"reason": "integration-test UC-160"}, nil)
		acancel()
		if lastErr == nil {
			attested = true
			break
		}
		if !strings.Contains(lastErr.Error(), "409") {
			t.Fatalf("attest storage retirement for stopped %s: %v", victim, lastErr)
		}
		time.Sleep(10 * time.Second) // still alive in gossip; the refusal is correct
	}
	if !attested {
		t.Fatalf("attestation for %s was still refused 3 minutes after its daemon stopped: %v", victim, lastErr)
	}
	after := list()
	if !after.has(victim) {
		t.Fatalf("attesting %s's retirement left no attestation row; the attestation IS the evidence and must stay listed", victim)
	}
	if o, open := after.obligation(victim); open {
		t.Fatalf("the attestation for %s did not discharge its obligation: %+v", victim, o)
	}
}

// UC-161 — the fleet-scale read paths stay bounded: a page is a page, and a
// caller is handed a cursor rather than the whole inventory.
//
// At 100k sandboxes an unbounded read is not slow, it is an outage: the
// response does not fit and the node building it does not survive it.
func TestFleetScaleReadsStayPaged(t *testing.T) {
	harness.Require(t, sc, "UC-161")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Enough placements that a limit of 1 must leave more behind.
	const want = 3
	for i := 0; i < want; i++ {
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-" + strconv.Itoa(i)})
		waitRunning(t, sb)
	}

	var page struct {
		Placements    []map[string]any `json:"placements"`
		NextPageToken string           `json:"next_page_token"`
	}
	if err := c.GetJSON(ctx, "/v1/cluster/sandbox-index?limit=1", &page); err != nil {
		t.Fatalf("read the sandbox index: %v", err)
	}
	if len(page.Placements) > 1 {
		t.Fatalf("limit=1 returned %d placements: the page size is not honoured, so a caller cannot bound the response", len(page.Placements))
	}
	if len(page.Placements) == 1 && page.NextPageToken == "" {
		// Only acceptable if there really is just one placement in the fleet.
		var all struct {
			Placements []map[string]any `json:"placements"`
		}
		if err := c.GetJSON(ctx, "/v1/cluster/sandbox-index?limit=1000", &all); err != nil {
			t.Fatalf("read the full sandbox index: %v", err)
		}
		if len(all.Placements) > 1 {
			t.Fatalf("the fleet holds %d placements but a limit=1 page returned no next_page_token: the rest are unreachable and a caller would conclude the fleet is one sandbox",
				len(all.Placements))
		}
	}

	// And the cursor must actually advance.
	if page.NextPageToken != "" {
		var second struct {
			Placements    []map[string]any `json:"placements"`
			NextPageToken string           `json:"next_page_token"`
		}
		if err := c.GetJSON(ctx, "/v1/cluster/sandbox-index?limit=1&page_token="+page.NextPageToken, &second); err != nil {
			t.Fatalf("read the second page: %v", err)
		}
		if second.NextPageToken == page.NextPageToken {
			t.Fatalf("the page token did not advance (%q repeated): a caller walking the fleet would loop forever", page.NextPageToken)
		}
	}
}

// UC-162 — the ingress topology gate.
//
// SCOPE, and why it is this and not a plan run. §7's own correction already
// dropped the live >10-node cluster: the DAEMON half needs more than
// MaxReplicatedIngressRouteNodes = 10 live ingress-capable members
// (internal/cluster/shards.go:28) and no scenario here reaches two, let alone
// eleven. The plan then proposed asserting the Terraform precondition with an
// 11-ingress plan. That does not work either: the module uses an S3 backend
// and AWS data sources, so `terraform plan` cannot run without initialising
// real state and credentials, and a failure would be indistinguishable from
// the precondition firing.
//
// What IS both free and real is the drift that actually bites an operator:
// the Terraform gate hardcodes 10 while the daemon's refusal comes from a Go
// constant, and `Terraform/validate/ingress.go` has no caller outside its own
// unit test. If the constant moves and the literal does not, Terraform
// happily provisions a tier the daemon rejects — the fleet is built and then
// refuses to serve. So this asserts the two agree, and that the escape hatch
// is the documented one.
func TestIngressTopologyGateMatchesTheDaemonConstant(t *testing.T) {
	harness.Require(t, sc, "UC-162")

	path, err := filepath.Abs(filepath.Join("..", "..", "Terraform", "nodes.tf"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(b)

	m := ingressPreconditionRe.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("no ingress-tier precondition found in %s. The gate that stops an operator provisioning a tier the daemon rejects is gone; Terraform/validate/ingress.go has no caller, so nothing else enforces it.", path)
	}
	limit, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("unparsable ingress limit %q: %v", m[1], err)
	}
	if limit != cluster.MaxReplicatedIngressRouteNodes {
		t.Fatalf("Terraform allows %d ingress-capable nodes but the daemon's MaxReplicatedIngressRouteNodes is %d. Terraform would provision a tier the daemon then refuses to serve — the fleet gets built and does not work.",
			limit, cluster.MaxReplicatedIngressRouteNodes)
	}
	if !strings.Contains(m[0], "var.shard_aware_ingress") {
		t.Fatalf("the ingress precondition has no shard_aware_ingress escape hatch: %q. A gate with no documented way past it gets deleted by whoever hits it.", m[0])
	}

	// Live half: whatever this scenario actually provisioned must be inside
	// the cap, or the run itself is in the unsupported topology.
	if !sc.Has(harness.CapCluster) {
		return
	}
	c := client(t)
	if n := len(clusterNodeIDs(t, c)); n > cluster.MaxReplicatedIngressRouteNodes {
		t.Fatalf("this deployment has %d members, past the %d-node replicated-ingress cap, with no shard-aware router asserted; the ingress route table is no longer fully replicated and a client can reach a node that does not know the route",
			n, cluster.MaxReplicatedIngressRouteNodes)
	}
}

// ingressPreconditionRe matches the condition line of the ingress-tier
// precondition in Terraform/nodes.tf.
var ingressPreconditionRe = regexp.MustCompile(`condition\s*=\s*length\(local\.ingress_node_names\)\s*<=\s*(\d+)\s*\|\|\s*var\.shard_aware_ingress`)
