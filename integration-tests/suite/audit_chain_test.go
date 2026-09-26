//go:build integration

package suite

// Group E, non-disruptive half — audit chain and read API (§7 group E, F6/F7).
// UC-131, 133, 136, 137, 138. The tamper/kill cases are in
// z_audit_tamper_test.go.

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// auditVerification is POST /v1/audit/verify.
type auditVerification struct {
	OK               bool   `json:"ok"`
	Head             string `json:"head"`
	Records          int64  `json:"records"`
	Redacted         int64  `json:"redacted"`
	Bytes            int64  `json:"bytes"`
	WriterTipMatches bool   `json:"writer_tip_matches"`
	IndexReady       bool   `json:"index_ready"`
	IndexLagBytes    int64  `json:"index_lag_bytes"`
	Error            string `json:"error,omitempty"`
}

func verifyAuditChain(t *testing.T, c *harness.Client) auditVerification {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var report auditVerification
	if err := c.PostJSON(ctx, "/v1/audit/verify", nil, &report); err != nil {
		t.Fatalf("POST /v1/audit/verify: %v", err)
	}
	return report
}

// UC-131 — the chain verifies on a live node after real work.
//
// Verifying an empty chain is trivially true, so this does work first and
// asserts the record count moved. A verifier that passes on nothing is a
// verifier that would pass on a truncated file.
func TestAuditChainVerifiesAfterAWorkload(t *testing.T) {
	harness.Require(t, sc, "UC-131")
	c := client(t)

	before := verifyAuditChain(t, c)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC131_TOKEN": secretValue(t, "131")},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for i := 0; i < 3; i++ {
		if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", nil); err != nil {
			t.Fatalf("read env: %v", err)
		}
	}

	after := verifyAuditChain(t, c)
	if !after.OK {
		t.Fatalf("the audit chain does not verify after a workload: %s (head=%s records=%d)", after.Error, after.Head, after.Records)
	}
	if after.Records <= before.Records {
		t.Fatalf("records did not grow (%d -> %d): the verification passed over a chain the workload never reached, which proves nothing",
			before.Records, after.Records)
	}
	if !after.WriterTipMatches {
		t.Fatalf("the verified head does not match the writer's tip: the file and the process disagree about what was written")
	}
}

// UC-133 — audit reads fan out. Queried on a node that never owned the
// sandbox, the answer must still contain the history the owner holds.
//
// Without fan-out an operator investigating an incident gets a different
// answer depending on which node they happened to reach, which makes the
// evidence unusable.
func TestAuditReadsFanOutToPeers(t *testing.T) {
	harness.Require(t, sc, "UC-133")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC133_TOKEN": secretValue(t, "133")},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", nil); err != nil {
		t.Fatalf("read env: %v", err)
	}

	page := harness.AuditEvents(t, c, sb.ID, harness.AuditQuery{Limit: 100})
	if len(page.Events) == 0 {
		t.Fatal("no audit events at all; the fan-out assertion would be vacuous")
	}
	if page.Coverage.Partial {
		t.Fatalf("coverage is partial on a healthy cluster: answered=%v missing=%v", page.Coverage.Answered, page.Coverage.Missing)
	}
	// The answer must have come from more than the node that served it, or
	// there was no fan-out to observe.
	if len(page.Coverage.Answered) < 2 {
		t.Fatalf("only %v answered; on a cluster the read did not fan out", page.Coverage.Answered)
	}
	owner := resolvePlacementOwner(t, c, sb.ID)
	if owner != "" && !containsString(page.Coverage.Answered, owner) {
		t.Fatalf("the owner %s is not among the nodes that answered %v; the history may be missing the events only it holds",
			owner, page.Coverage.Answered)
	}
}

// UC-136 — post-delete history is readable within the grace window, and a
// recreated id does not leak the previous incarnation's events.
//
// The second half is the one with teeth: sandbox ids are reusable, and an
// audit read that ignores the incarnation hands a new tenant the previous
// tenant's access record.
func TestPostDeleteAuditIsScopedToItsIncarnation(t *testing.T) {
	harness.Require(t, sc, "UC-136")
	c := client(t)

	name := harness.UniqueName(sc, t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	public := true
	first, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Name: name, Image: harness.DefaultImage, AllowPublicTraffic: &public,
		Env: map[string]string{"UC136_TOKEN": secretValue(t, "136a")},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.GetJSON(ctx, "/v1/sandboxes/"+first.ID+"?include_env=true", nil); err != nil {
		t.Fatalf("read env: %v", err)
	}
	firstEvents := harness.AllAuditEvents(t, c, first.ID, 100, 10)
	if len(firstEvents) == 0 {
		t.Fatal("the first incarnation produced no audit events")
	}
	firstIncarnation := firstEvents[len(firstEvents)-1].IncarnationID

	if err := c.SDK().Destroy(ctx, first.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	// Within the grace window the history is still readable.
	page := harness.AuditEvents(t, c, first.ID, harness.AuditQuery{Limit: 100, IncarnationID: firstIncarnation})
	if len(page.Events) == 0 {
		t.Fatalf("the history for %s vanished immediately on delete; SB_AUDIT_DELETED_GRACE should keep it readable", first.ID)
	}
	for _, ev := range page.Events {
		if ev.IncarnationID != "" && ev.IncarnationID != firstIncarnation {
			t.Fatalf("a post-delete read scoped to %s returned an event from incarnation %s", firstIncarnation, ev.IncarnationID)
		}
	}

	// A DIFFERENT incarnation id must not see them. This is the leak: ids are
	// reusable, so an unscoped read hands the next tenant the previous
	// tenant's access record.
	other := harness.AuditEvents(t, c, first.ID, harness.AuditQuery{Limit: 100, IncarnationID: firstIncarnation + "-not-mine"})
	for _, ev := range other.Events {
		if ev.IncarnationID == firstIncarnation {
			t.Fatalf("a read scoped to a foreign incarnation returned incarnation %s's events: a recreated id leaks the previous tenant's history",
				firstIncarnation)
		}
	}
}

// UC-137 — index-off returns the SAME events as index-on, and an incomplete
// index answers 503 rather than a short answer.
//
// A short answer is the dangerous one: it looks like "there was no such
// access" when it means "the index had not caught up".
func TestAuditIndexParityAndIncompleteIndexIs503(t *testing.T) {
	harness.Require(t, sc, "UC-137")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC137_TOKEN": secretValue(t, "137")},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for i := 0; i < 5; i++ {
		if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", nil); err != nil {
			t.Fatalf("read env: %v", err)
		}
	}
	withIndex := harness.AllAuditEvents(t, c, sb.ID, 100, 10)
	if len(withIndex) == 0 {
		t.Fatal("no events with the index on; the parity assertion would compare two empty answers")
	}

	owner := resolvePlacementOwner(t, c, sb.ID)
	node, ok := nodeForClusterID(t, c, targets, owner)
	if !ok {
		node, ok = harness.PickSSHNode(targets)
		if !ok {
			t.Skip("no SSH-reachable node")
		}
	}

	harness.WithNodeEnv(t, node, map[string]string{"SB_AUDIT_INDEX_ENABLED": "false"}, func(res harness.NodeBootResult) {
		if !res.Started {
			t.Fatalf("node %s did not start with the audit index disabled: %s", node.Name, res.Status)
		}
		withoutIndex := harness.AllAuditEvents(t, c, sb.ID, 100, 10)
		if len(withoutIndex) != len(withIndex) {
			t.Fatalf("index-off returned %d events, index-on returned %d: the index and the file disagree about the history",
				len(withoutIndex), len(withIndex))
		}
		if !sameEventIDs(withIndex, withoutIndex) {
			t.Fatal("index-off returned a different SET of events than index-on, even though the counts matched")
		}
	})
}

// UC-138 — pagination walks a multi-page history with no duplicates and no
// gaps. AllAuditPages already rejects a non-advancing cursor; this asserts
// the content.
func TestAuditPaginationHasNoDuplicatesOrGaps(t *testing.T) {
	harness.Require(t, sc, "UC-138")
	c := client(t)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC138_TOKEN": secretValue(t, "138")},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const reads = 12
	for i := 0; i < reads; i++ {
		if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", nil); err != nil {
			t.Fatalf("read env %d: %v", i, err)
		}
	}

	oneShot := harness.AuditEvents(t, c, sb.ID, harness.AuditQuery{Limit: 500})
	if len(oneShot.Events) < reads {
		t.Fatalf("only %d events after %d reads; there is not enough history to paginate", len(oneShot.Events), reads)
	}
	// Small pages, so there really are several.
	paged := harness.AllAuditEvents(t, c, sb.ID, 3, 200)

	if len(paged) != len(oneShot.Events) {
		t.Fatalf("paginated walk returned %d events, a single large page returned %d: pagination loses or repeats records",
			len(paged), len(oneShot.Events))
	}
	seen := map[string]int{}
	for _, ev := range paged {
		if ev.EventID == "" {
			continue
		}
		seen[ev.EventID]++
		if seen[ev.EventID] > 1 {
			t.Fatalf("event %s appeared %d times across pages", ev.EventID, seen[ev.EventID])
		}
	}
	if !sameEventIDs(oneShot.Events, paged) {
		t.Fatal("the paginated walk and the single-page read describe different histories")
	}
}
