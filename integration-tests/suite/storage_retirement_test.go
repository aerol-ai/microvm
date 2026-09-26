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

// storageRetirements is GET /v1/cluster/storage-retirements.
type storageRetirements struct {
	Retirements []struct {
		NodeID     string `json:"node_id"`
		AttestedAt string `json:"attested_at"`
		Actor      string `json:"actor"`
		Reason     string `json:"reason"`
	} `json:"retirements"`
}

func (r storageRetirements) has(nodeID string) bool {
	for _, rec := range r.Retirements {
		if rec.NodeID == nodeID {
			return true
		}
	}
	return false
}

// UC-160 — draining a worker raises a storage-retirement obligation, and
// attesting it clears the obligation.
//
// The obligation is how an operator knows a decommissioned node still holds
// data that must be destroyed. A drain that raises nothing means a node can
// leave the fleet with sealed material on its disk and no record saying so.
func TestDrainRaisesAStorageRetirementObligation(t *testing.T) {
	harness.Require(t, sc, "UC-160")
	c := client(t)
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}

	// A drained node must be holding something, or the obligation has no
	// subject and its absence would prove nothing.
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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer ccancel()
		// Revoke first, then uncordon: an attested retirement left behind
		// would tell every later case the node's storage is already clean.
		_ = c.Delete(cctx, "/v1/cluster/nodes/"+victim+"/storage-retired")
		if err := c.PostJSON(cctx, "/v1/cluster/nodes/"+victim+"/uncordon", nil, nil); err != nil {
			t.Errorf("RESTORE FAILED: node %s left drained: %v", victim, err)
		}
	})
	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+victim+"/drain", nil, nil); err != nil {
		t.Fatalf("drain %s: %v", victim, err)
	}

	deadline := time.Now().Add(4 * time.Minute)
	raised := false
	for time.Now().Before(deadline) {
		var recs storageRetirements
		if err := c.GetJSON(ctx, "/v1/cluster/storage-retirements", &recs); err != nil {
			t.Fatalf("list storage retirements: %v", err)
		}
		if recs.has(victim) {
			raised = true
			break
		}
		time.Sleep(15 * time.Second)
	}
	if !raised {
		t.Fatalf("draining %s raised no storage-retirement obligation: the node can leave the fleet with sealed material on its disk and nothing recording that it must be destroyed", victim)
	}

	// Attesting must clear it. An obligation that cannot be discharged is an
	// alert that never goes away, which is an alert nobody reads.
	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+victim+"/storage-retired",
		map[string]any{"reason": "integration-test UC-160"}, nil); err != nil {
		t.Fatalf("attest storage retirement for %s: %v", victim, err)
	}
	var after storageRetirements
	if err := c.GetJSON(ctx, "/v1/cluster/storage-retirements", &after); err != nil {
		t.Fatalf("re-list storage retirements: %v", err)
	}
	if !after.has(victim) {
		t.Fatalf("attesting %s's retirement removed the record entirely; the attestation IS the evidence and must survive as one", victim)
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
