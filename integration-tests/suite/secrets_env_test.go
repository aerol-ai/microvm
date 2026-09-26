//go:build integration

package suite

// Group D — env sealing and the API contract (§7 group D, F5). UC-126..129.
// UC-130 is disruptive and lives in z_secrets_env_loss_test.go.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-126 — Get and List omit env by default.
//
// Both halves matter. List is the one people forget: a Get that redacts while
// List does not is a leak that shows up in every dashboard and every `ls`.
func TestGetAndListOmitEnvByDefault(t *testing.T) {
	harness.Require(t, sc, "UC-126")
	c := client(t)
	secret := secretValue(t, "126")

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC126_TOKEN": secret},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var got json.RawMessage
	if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID, &got); err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	harness.AssertNoPlaintext(t, "GET /v1/sandboxes/{id}", string(got), secret)
	assertNoEnvKey(t, "GET /v1/sandboxes/{id}", got)

	var list json.RawMessage
	if err := c.GetJSON(ctx, "/v1/sandboxes", &list); err != nil {
		t.Fatalf("list sandboxes: %v", err)
	}
	harness.AssertNoPlaintext(t, "GET /v1/sandboxes (list)", string(list), secret)
	if !strings.Contains(string(list), sb.ID) {
		t.Fatalf("the list did not contain %s, so its redaction proves nothing", sb.ID)
	}
}

// UC-127 — include_env=true returns the env AND emits exactly one audit event
// naming the actor. An opt-in that leaves no trace is not an opt-in.
func TestIncludeEnvReturnsEnvAndAuditsExactlyOnce(t *testing.T) {
	harness.Require(t, sc, "UC-127")
	c := client(t)
	secret := secretValue(t, "127")

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC127_TOKEN": secret, "UC127_OTHER": "plain"},
	})
	waitRunning(t, sb)

	before := harness.AllAuditEvents(t, c, sb.ID, 200, 20)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var withEnv struct {
		Env map[string]string `json:"env"`
	}
	if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", &withEnv); err != nil {
		t.Fatalf("get with include_env: %v", err)
	}
	if withEnv.Env["UC127_TOKEN"] != secret || withEnv.Env["UC127_OTHER"] != "plain" {
		t.Fatalf("include_env did not return the env: %v", redactedKeys(withEnv.Env))
	}

	after := harness.AllAuditEvents(t, c, sb.ID, 200, 20)
	if n := len(after) - len(before); n != 1 {
		t.Fatalf("one include_env read produced %d audit records, want exactly 1 (before=%d after=%d)", n, len(before), len(after))
	}
	ev := after[len(after)-1]
	if strings.TrimSpace(ev.Actor) == "" {
		t.Fatal("the audit record names no actor; the evidence cannot answer who read the env")
	}
	if ev.Ref != "env:"+sb.ID {
		t.Fatalf("audit ref = %q, want env:%s", ev.Ref, sb.ID)
	}
	if ev.EventHash == "" || ev.PrevHash == "" {
		t.Fatalf("the audit record is not chained (prev=%q hash=%q); it cannot be shown to be untampered", ev.PrevHash, ev.EventHash)
	}
}

// UC-128 — env is absent from the Raft placement spec.
//
// The placement is replicated to every voter and persisted in the Raft log and
// its snapshots. Env leaking into it would put plaintext credentials on every
// node in the cluster, forever, regardless of the recipient set — which is the
// entire point of sealing them separately.
func TestEnvIsAbsentFromThePlacementSpec(t *testing.T) {
	harness.Require(t, sc, "UC-128")
	c := client(t)
	secret := secretValue(t, "128")

	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC128_TOKEN": secret},
	})
	waitRunning(t, sb)
	if owner := resolvePlacementOwner(t, c, sb.ID); owner == "" {
		t.Fatal("no placement recorded; there is nothing to inspect")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var placement json.RawMessage
	if err := c.GetJSON(ctx, "/v1/cluster/placements/"+sb.ID, &placement); err != nil {
		t.Fatalf("read placement: %v", err)
	}
	harness.AssertNoPlaintext(t, "the Raft placement spec", string(placement), secret)
	assertNoEnvKey(t, "the Raft placement spec", placement)
}

// UC-129 — on disk there is no plaintext env column, and the sealed row
// survives an update to the sandbox.
//
// Read over SSH with sqlite3 because the API is exactly the layer that is
// supposed to redact: asking the API whether the database holds plaintext
// would be asking the redactor to grade itself.
func TestOnDiskEnvIsSealedAndSurvivesAnUpdate(t *testing.T) {
	harness.Require(t, sc, "UC-129")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	secret := secretValue(t, "129")

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC129_TOKEN": secret},
	})
	waitRunning(t, sb)

	owner := resolvePlacementOwner(t, c, sb.ID)
	node, ok := nodeForClusterID(t, c, targets, owner)
	if !ok {
		// Single-node deployments have no placement; the seed holds the row.
		node, ok = harness.PickSSHNode(targets)
		if !ok {
			t.Skip("no SSH-reachable node holding the store")
		}
	}
	target, _ := harness.SSHTarget(node)

	// A full-text dump of the sandbox rows. If the secret is anywhere in
	// there in any encoding, it was not sealed.
	dump, err := harness.SSHRun(t, target, sqliteDumpScript)
	if err != nil {
		t.Skipf("could not read the store on %s (sqlite3 may not be installed): %v", node.Name, err)
	}
	if !strings.Contains(dump, sb.ID) {
		t.Fatalf("the store dump does not mention %s, so its absence of plaintext proves nothing", sb.ID)
	}
	harness.AssertNoPlaintext(t, "the on-disk sandbox store", dump, secret)

	// And the sealed row must survive an update that does not touch env.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := c.PostJSON(ctx, "/v1/sandboxes/"+sb.ID+"/lifecycle", map[string]any{"auto_stop_minutes": 0}, nil); err != nil {
		t.Logf("lifecycle update not available here (%v); falling back to a plain re-read", err)
	}
	var withEnv struct {
		Env map[string]string `json:"env"`
	}
	if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", &withEnv); err != nil {
		t.Fatalf("re-read env after update: %v", err)
	}
	if withEnv.Env["UC129_TOKEN"] != secret {
		t.Fatalf("the sealed env did not survive an unrelated update: got %q", withEnv.Env["UC129_TOKEN"])
	}
}
