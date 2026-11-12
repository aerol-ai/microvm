//go:build integration

package suite

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// failoverDeadlineSlack is how far the E2B deadline and created_at may move
// across a failover: the cluster records the first create in whole seconds,
// at the placement reserve just before the owner stamps its row.
const failoverDeadlineSlack = 3 * time.Second

// UC-705 — a failover recreate keeps the sandbox's E2B deadline and its
// created_at. The recreate used to stamp the new row with the recreate time
// while replaying the age timers unchanged, so every deadline moved out by the
// time from the first create to the recreate (the E2B timeout is stored as an
// age: elapsed time plus the timeout). Kill the owner's daemon, wait for the
// recreate on a peer, and read both back.
func TestFailoverKeepsE2BDeadline(t *testing.T) {
	harness.Require(t, sc, "UC-705")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (drop --no-disruptive)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	// /v1, since E2B's create has no failover field; the E2B routes serve it.
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:     harness.UniqueName(sc, t),
		Runtime:  "docker",
		Failover: &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), failoverOpenTimeout+5*time.Minute)
	defer cancel()
	if st, body := fcDo(t, ctx, http.MethodPost, "", "/e2b/sandboxes/"+sb.ID+"/timeout", map[string]any{"timeout": 1800}, nil); st != http.StatusNoContent {
		t.Fatalf("E2B setTimeout = %d, want 204; body=%s", st, string(body))
	}
	endBefore, createdBefore := e2bDeadlineAndCreated(t, ctx, sb.ID)

	owner := resolvePlacementOwner(t, c, sb.ID)
	if owner == "" {
		t.Fatal("no placement owner recorded; there is nothing to kill")
	}
	victim, ok := nodeForClusterID(t, c, targets, owner)
	if !ok {
		t.Skipf("owner %s is not a node this suite can reach", owner)
	}
	requireNonSeedVictim(t, victim)
	killedAt := time.Now()
	t.Cleanup(harness.KillNodeDaemon(t, victim))
	newOwner := awaitNewOwner(t, c, sb.ID, owner, failoverOpenTimeout)
	// Not waitRunning: sb still holds "started" from before the kill, so it
	// would return at once. The reassign lands before the new owner has
	// rebuilt the row, and until then a read there answers 404.
	endAfter, createdAfter := awaitE2BDeadlineAndCreated(t, ctx, sb.ID)
	recreatedAfter := time.Since(createdBefore)
	endShift, createdShift := endAfter.Sub(endBefore), createdAfter.Sub(createdBefore)
	harness.ReportDetail(t, "Owner %s killed, recreated on %s %s after the kill (%s after the first create). "+
		"E2B endAt moved %s (want within %s; the old recreate moved it by the time since the first create). created_at moved %s.",
		owner, newOwner, time.Since(killedAt).Round(time.Second), recreatedAfter.Round(time.Second),
		endShift, failoverDeadlineSlack, createdShift)

	if endShift.Abs() > failoverDeadlineSlack {
		t.Errorf("E2B endAt moved %s across the failover (%s → %s), want within %s", endShift, endBefore, endAfter, failoverDeadlineSlack)
	}
	if createdShift.Abs() > failoverDeadlineSlack {
		t.Errorf("created_at moved %s across the failover (%s → %s), want within %s", createdShift, createdBefore, createdAfter, failoverDeadlineSlack)
	}
}

// awaitE2BDeadlineAndCreated is e2bDeadlineAndCreated once the sandbox's
// new owner serves it: a 404 there means the recreate has not written the
// row yet.
func awaitE2BDeadlineAndCreated(t *testing.T, ctx context.Context, id string) (endAt, createdAt time.Time) {
	t.Helper()
	for {
		st, body := fcDo(t, ctx, http.MethodGet, "", "/e2b/sandboxes/"+id, nil, nil)
		if st == http.StatusOK {
			return e2bDeadlineAndCreated(t, ctx, id)
		}
		if st != http.StatusNotFound || ctx.Err() != nil {
			t.Fatalf("E2B get %s after the failover = %d; body=%s", id, st, string(body))
		}
		time.Sleep(2 * time.Second)
	}
}

// e2bDeadlineAndCreated reads a sandbox's E2B endAt and its /v1 created_at.
func e2bDeadlineAndCreated(t *testing.T, ctx context.Context, id string) (endAt, createdAt time.Time) {
	t.Helper()
	st, body := fcDo(t, ctx, http.MethodGet, "", "/e2b/sandboxes/"+id, nil, nil)
	if st != http.StatusOK {
		t.Fatalf("E2B get %s = %d; body=%s", id, st, string(body))
	}
	var e2b struct {
		EndAt string `json:"endAt"`
	}
	fcDecode(t, body, &e2b)
	st, body = fcDo(t, ctx, http.MethodGet, "", "/v1/sandboxes/"+id, nil, nil)
	if st != http.StatusOK {
		t.Fatalf("v1 get %s = %d; body=%s", id, st, string(body))
	}
	var v1 struct {
		CreatedAt time.Time `json:"created_at"`
	}
	fcDecode(t, body, &v1)
	endAt, err := time.Parse(time.RFC3339Nano, e2b.EndAt)
	if err != nil || v1.CreatedAt.IsZero() {
		t.Fatalf("sandbox %s: endAt %q (%v), created_at %s", id, e2b.EndAt, err, v1.CreatedAt)
	}
	return endAt, v1.CreatedAt
}
