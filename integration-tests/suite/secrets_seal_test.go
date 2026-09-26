//go:build integration

package suite

// Group A — sealing and fan-out (plans/integration-test-security.md §7,
// F1/F2). UC-110..116.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// secretValue returns a high-entropy value that cannot occur by accident in a
// response body. A short or guessable value would make the leak sweep either
// miss a real leak or trip over unrelated text.
func secretValue(t *testing.T, tag string) string {
	t.Helper()
	return fmt.Sprintf("uc-%s-%d-Zq7xR2pL9vKw", tag, time.Now().UnixNano())
}

// UC-110 — sealed credentials: the sandbox runs, the material is not readable
// by default, and reading it back emits exactly one audit record that names
// the actor and carries no plaintext.
//
// The plan phrased this as "exactly one secret.seal audit event". No such
// event exists: internal/service emits on OPEN, not on seal (the stored kinds
// are secret_open, egress, gap, retention_checkpoint, retention_redacted —
// secret_audit.go:51-58 — and the only emitter is beginSecretAuditOwned, on
// the decrypt paths). Asserting on a seal event would have been a test of
// something the product never writes, so this asserts the observable
// equivalent instead.
func TestSealedCredentialsAreOpaqueAndAudited(t *testing.T) {
	harness.Require(t, sc, "UC-110")
	c := client(t)
	secret := secretValue(t, "110")

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC110_TOKEN": secret},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// The default read must not carry it, in any encoding.
	var plain json.RawMessage
	if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID, &plain); err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	harness.AssertNoPlaintext(t, "GET /v1/sandboxes/{id}", string(plain), secret)

	before := len(harness.AllAuditEvents(t, c, sb.ID, 200, 20))

	var withEnv struct {
		Env map[string]string `json:"env"`
	}
	if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", &withEnv); err != nil {
		t.Fatalf("get sandbox with env: %v", err)
	}
	if withEnv.Env["UC110_TOKEN"] != secret {
		t.Fatalf("sealed env did not round-trip: got %q", withEnv.Env["UC110_TOKEN"])
	}

	events := harness.AllAuditEvents(t, c, sb.ID, 200, 20)
	if len(events) <= before {
		t.Fatalf("reading the sealed env produced no audit record (%d events before and after)", before)
	}
	// Exactly one new record for this read. More than one would mean the read
	// path audits twice and an operator cannot count accesses; none would mean
	// the material can be read without leaving evidence.
	if got := len(events) - before; got != 1 {
		t.Fatalf("one include_env read produced %d audit records, want exactly 1", got)
	}

	newest := events[len(events)-1]
	if newest.Kind != "secret_open" {
		t.Fatalf("audit record kind = %q, want secret_open", newest.Kind)
	}
	if newest.Ref != "env:"+sb.ID {
		t.Fatalf("audit record ref = %q, want env:%s", newest.Ref, sb.ID)
	}
	if newest.Result != "success" {
		t.Fatalf("audit record result = %q, want success", newest.Result)
	}
	if strings.TrimSpace(newest.Actor) == "" {
		t.Fatal("audit record names no actor; the evidence cannot answer who read the secret")
	}

	// The evidence itself must not become the leak.
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	harness.AssertNoPlaintext(t, "the audit history", string(raw), secret)
}

// UC-111 — an HA create reaches failover_ready, and the recipient set is
// genuinely larger than the owner alone.
//
// The holder-count half is what stops this from passing vacuously: a
// single-recipient set makes failover_ready true while there is nowhere for
// the sandbox to fail over to.
func TestHACreateReachesFailoverReadyWithRealRecipients(t *testing.T) {
	harness.Require(t, sc, "UC-111")
	c := client(t)

	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC111_TOKEN": secretValue(t, "111")},
	})

	view := harness.AwaitSecretHolders(t, c, sb.ID, 2*time.Minute, func(v harness.SecretHoldersView) bool {
		return len(v.Holders) >= 2
	})
	owner := resolvePlacementOwner(t, c, sb.ID)
	if owner == "" {
		t.Fatal("no placement owner recorded for an HA sandbox")
	}
	if !slices.Contains(view.Holders, owner) {
		t.Fatalf("owner %q is not in the holder set %v; the sandbox cannot open its own secret", owner, view.Holders)
	}
	if len(view.Holders) < 2 {
		t.Fatalf("holder set %v has no peer; failover_ready is vacuous", view.Holders)
	}
	if view.SealGeneration < 1 {
		t.Fatalf("seal generation = %d, want at least 1", view.SealGeneration)
	}
}

// UC-112 — the sealed row is on every recipient and on no one else.
//
// The operator holders view reports the recipient set the owner INTENDS. Only
// the peer HEAD says whether the bytes arrived, and only the negative half
// says the fan-out was scoped rather than broadcast.
func TestSealedRowIsPresentOnRecipientsAndAbsentElsewhere(t *testing.T) {
	harness.Require(t, sc, "UC-112")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC112_TOKEN": secretValue(t, "112")},
	})
	view := harness.AwaitSecretHolders(t, c, sb.ID, 2*time.Minute, func(v harness.SecretHoldersView) bool {
		return len(v.Holders) >= 2
	})

	checked, nonRecipients := 0, 0
	for _, node := range targets.Nodes {
		if _, ok := harness.SSHTarget(node); !ok {
			continue
		}
		nodeID := heteroNodeID(t, c, targets, node.Name)
		probe := harness.ProbePeerSecret(t, node, sb.ID)
		if probe.Err != nil {
			t.Fatalf("peer probe on %s: %v", node.Name, probe.Err)
		}
		checked++
		want := slices.Contains(view.Holders, nodeID)
		switch {
		case want && !probe.Present():
			t.Fatalf("%s (%s) is in the recipient set %v but does not hold the row (status %d): the fan-out reported success without delivering",
				node.Name, nodeID, view.Holders, probe.Status)
		case !want && !probe.Absent():
			t.Fatalf("%s (%s) is NOT a recipient but answered %d for the sealed row: the fan-out was broadcast, not scoped",
				node.Name, nodeID, probe.Status)
		}
		if !want {
			nonRecipients++
		}
	}
	if checked == 0 {
		t.Fatal("no node was probed; the assertion would have passed having checked nothing")
	}
	// The negative half is the interesting one. Without a non-recipient in the
	// fleet this case proves only "the row is everywhere", which is what it is
	// supposed to rule out.
	if nonRecipients == 0 {
		t.Logf("every reachable node is a recipient (%d of %d); the negative half of this case did not get to run here", len(view.Holders), checked)
	}
}

// UC-113 — the peer-visible sealed state is stable under repeated observation:
// one row, one generation, one recipient set.
//
// SCOPE, stated plainly: a true replay of the fan-out POST needs the sealed
// body, which only the owner holds and which no read API exposes — by design,
// and #479 deliberately did not change that. What is assertable from outside
// is the invariant the replay exists to preserve, observed through the peer
// HEAD and the operator view: nothing about looking at the state may change
// it. That catches the regression classes that actually bite — a read path
// that bumps a generation, and a fan-out that re-runs on observation and
// double-books the recipient set — but it does NOT prove the PUT handler's
// own conflict behaviour, which stays covered offline.
func TestPeerSecretStateIsStableUnderRepeatedObservation(t *testing.T) {
	harness.Require(t, sc, "UC-113")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC113_TOKEN": secretValue(t, "113")},
	})
	first := harness.AwaitSecretHolders(t, c, sb.ID, 2*time.Minute, func(v harness.SecretHoldersView) bool {
		return len(v.Holders) >= 2
	})

	node, ok := pickSSHNodeHolding(t, c, targets, first.Holders)
	if !ok {
		t.Skip("no SSH-reachable recipient to probe")
	}
	for i := 0; i < 3; i++ {
		probe := harness.ProbePeerSecret(t, node, sb.ID)
		if probe.Err != nil {
			t.Fatalf("peer probe %d on %s: %v", i+1, node.Name, probe.Err)
		}
		if !probe.Present() {
			t.Fatalf("peer probe %d on %s: status %d — a repeated read lost the row", i+1, node.Name, probe.Status)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	second, err := c.SecretHoldersFor(ctx, sb.ID)
	if err != nil {
		t.Fatalf("re-read holders: %v", err)
	}
	if second.SealGeneration != first.SealGeneration {
		t.Fatalf("seal generation moved from %d to %d without a membership change; observation is mutating state",
			first.SealGeneration, second.SealGeneration)
	}
	if second.Version != first.Version || second.Ref != first.Ref {
		t.Fatalf("the sealed row was rewritten under observation: version %d->%d, ref %q->%q",
			first.Version, second.Version, first.Ref, second.Ref)
	}
	if strings.Join(second.Holders, ",") != strings.Join(first.Holders, ",") {
		t.Fatalf("the recipient set changed under observation: %v -> %v; the fan-out re-ran and double-booked",
			first.Holders, second.Holders)
	}
	if !second.Converged() {
		t.Fatalf("outstanding outbox work appeared with no trigger: put=%v delete=%v", second.PendingPut, second.PendingDelete)
	}
}

// UC-114 — a caller that reaches the internal port without a peer identity is
// refused. Network position is not entitlement.
func TestPeerSecretPushRefusesAForeignIdentity(t *testing.T) {
	harness.Require(t, sc, "UC-114")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	node, ok := harness.PickSSHNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}
	c := client(t)
	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC114_TOKEN": secretValue(t, "114")},
	})

	// Sanity: with the node's own certificate the same request is served, so a
	// refusal below is about the identity and not about the URL being wrong.
	if probe := harness.ProbePeerSecret(t, node, sb.ID); probe.Err != nil {
		t.Fatalf("control probe with the node's own certificate failed: %v", probe.Err)
	} else if probe.Status == 403 || probe.Status == 401 {
		t.Fatalf("the node's OWN certificate was refused (%d); this case cannot distinguish identity from URL", probe.Status)
	}

	for _, tc := range []struct {
		name   string
		bearer string
	}{
		{name: "no client certificate at all", bearer: ""},
		{name: "operator PAT instead of a peer certificate", bearer: sc.PAT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := harness.ProbePeerSecretUnauthenticated(t, node, sb.ID, tc.bearer)
			if probe.Err != nil {
				t.Fatalf("probe: %v", probe.Err)
			}
			if probe.Status >= 200 && probe.Status < 300 {
				t.Fatalf("the internal secret route served a caller with %s (status %d)", tc.name, probe.Status)
			}
			if probe.Status == 404 {
				t.Fatalf("the route answered 404 for %s; a missing-route answer would hide a missing authz check", tc.name)
			}
		})
	}
}

// UC-115 — an HA create that cannot reach any peer is retracted, not left
// half-made. A sandbox that exists but whose secret reached nobody is worse
// than a failed create: it looks healthy and cannot fail over.
func TestZeroAckHACreateIsRetracted(t *testing.T) {
	harness.Require(t, sc, "UC-115")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps, or drop --no-disruptive)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	// Refusing the internal listener on every node makes every peer ACK fail
	// while leaving the public API reachable, which is what isolates the
	// fan-out from everything else that could fail a create.
	restore := blockInternalListenerEverywhere(t, targets)
	defer restore()

	name := harness.UniqueName(sc, t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	public := true
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Name:               name,
		Image:              harness.DefaultImage,
		AllowPublicTraffic: &public,
		Env:                map[string]string{"UC115_TOKEN": secretValue(t, "115")},
		Failover:           &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
	})
	if err == nil {
		// Not an automatic failure: if it succeeded, it must be genuinely
		// ready, which would mean the block did not take effect.
		t.Cleanup(func() {
			cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
			defer ccancel()
			_ = c.SDK().Destroy(cctx, sb.ID)
		})
		t.Fatalf("an HA create succeeded (%s) with every peer unreachable; it should have been retracted", sb.ID)
	}
	t.Logf("HA create failed as intended: %v", err)

	// And it must leave nothing behind. An orphan row is the failure this case
	// exists to catch — the create said no, so nothing may remain saying yes.
	restore()
	assertNoSandboxNamed(t, c, name)
}

// UC-116 — the recipient-set size tracks SB_SECRET_RECIPIENT_BACKUP_COUNT,
// capped at what the cluster can actually supply.
func TestRecipientSetSizeTracksTheBackupCount(t *testing.T) {
	harness.Require(t, sc, "UC-116")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	members := len(seedFirstNodeNames(targets))
	if members < 2 {
		t.Skipf("recipient-set sizing needs at least 2 nodes, have %d", members)
	}

	sizes := map[string]int{}
	for _, count := range []string{"1", "3"} {
		harness.WithClusterEnv(t, targets, map[string]string{"SB_SECRET_RECIPIENT_BACKUP_COUNT": count}, func(res map[string]harness.NodeBootResult) {
			for name, r := range res {
				if !r.Started {
					t.Fatalf("node %s did not start with SB_SECRET_RECIPIENT_BACKUP_COUNT=%s: %s", name, count, r.Status)
				}
			}
			sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
				Env: map[string]string{"UC116_TOKEN": secretValue(t, "116-"+count)},
			})
			view := harness.AwaitSecretHolders(t, c, sb.ID, 2*time.Minute, func(v harness.SecretHoldersView) bool {
				return len(v.Holders) >= 1
			})
			sizes[count] = len(view.Holders)
		})
	}

	// The knob must move the answer, and it must never exceed the fleet.
	if sizes["3"] <= sizes["1"] && members > sizes["1"] {
		t.Fatalf("backup count 1 gave %d holders and 3 gave %d on a %d-node cluster; the knob has no effect",
			sizes["1"], sizes["3"], members)
	}
	for count, got := range sizes {
		if got > members {
			t.Fatalf("backup count %s produced %d holders on a %d-node cluster; the cap is not applied", count, got, members)
		}
	}
	t.Logf("recipient-set sizes: count=1 -> %d holders, count=3 -> %d holders (%d nodes)", sizes["1"], sizes["3"], members)
}
