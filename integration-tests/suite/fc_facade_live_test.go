//go:build integration

package suite

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-252 — Daytona create a sandbox runs end to end (first live Daytona create).
func TestDaytonaCreateLive(t *testing.T) {
	harness.Require(t, sc, "UC-252")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	st, body := fcDo(t, ctx, http.MethodPost, "", "/daytona/sandbox", map[string]any{"snapshot": "alpine:3.20"}, nil)
	if st != http.StatusCreated {
		t.Fatalf("Daytona create = %d, want 201; body=%s", st, string(body))
	}
	var r idResponse
	fcDecode(t, body, &r)
	if r.ID == "" {
		t.Fatalf("Daytona create returned no id: %s", string(body))
	}
	destroySandbox(t, r.ID)
}

// UC-253 — E2B create a sandbox runs end to end (first live E2B create).
func TestE2BCreateLive(t *testing.T) {
	harness.Require(t, sc, "UC-253")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	st, body := fcDo(t, ctx, http.MethodPost, "", "/e2b/sandboxes", map[string]any{"templateID": "base"}, nil)
	if st != http.StatusCreated {
		t.Fatalf("E2B create = %d, want 201; body=%s", st, string(body))
	}
	var r struct {
		SandboxID string `json:"sandboxID"`
	}
	fcDecode(t, body, &r)
	if r.SandboxID == "" {
		t.Fatalf("E2B create returned no sandboxID: %s", string(body))
	}
	destroySandbox(t, r.SandboxID)
}

// UC-254 — a Daytona create in a cluster is placed on a real runtime node.
func TestDaytonaCreateClusterPlaced(t *testing.T) {
	harness.Require(t, sc, "UC-254")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	st, body := fcDo(t, ctx, http.MethodPost, "", "/daytona/sandbox", map[string]any{"snapshot": "alpine:3.20"}, nil)
	if st != http.StatusCreated {
		t.Fatalf("Daytona cluster create = %d, want 201; body=%s", st, string(body))
	}
	var r idResponse
	fcDecode(t, body, &r)
	destroySandbox(t, r.ID)
	owner, err := c.OwnerNodeID(ctx, r.ID)
	if err != nil || owner == "" {
		t.Fatalf("Daytona-created sandbox %s has no cluster placement: %v", r.ID, err)
	}
}

// UC-255 — a get for a missing sandbox is a 404 on v1 and on Daytona.
func TestMissingSandboxIs404AcrossFacades(t *testing.T) {
	harness.Require(t, sc, "UC-255")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	missing := "sb-uc255-" + harness.UniqueName(sc, t)
	if st, body := fcDo(t, ctx, http.MethodGet, "", "/v1/sandboxes/"+missing, nil, nil); st != http.StatusNotFound {
		t.Fatalf("v1 get missing = %d, want 404; body=%s", st, string(body))
	}
	if st, body := fcDo(t, ctx, http.MethodGet, "", "/daytona/sandbox/"+missing, nil, nil); st != http.StatusNotFound {
		t.Fatalf("Daytona get missing = %d, want 404; body=%s", st, string(body))
	}
}

// runloopWaitRunning polls a devbox until it reports running.
func runloopWaitRunning(t *testing.T, ctx context.Context, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		st, body := fcDo(t, ctx, http.MethodGet, "", "/runloop/v1/devboxes/"+id, nil, nil)
		if st == http.StatusOK {
			var dv struct {
				Status string `json:"status"`
			}
			fcDecode(t, body, &dv)
			if strings.EqualFold(dv.Status, "running") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("devbox %s never reached running (last status body=%s)", id, string(body))
		}
		time.Sleep(4 * time.Second)
	}
}

// UC-256 — Runloop exec with a repeated command_id replays the same execution
// (the durable exec ledger moved to internal/service in D14).
func TestRunloopExecLedgerDedup(t *testing.T) {
	harness.Require(t, sc, "UC-256")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	id := runloopCreateDevbox(t, ctx)
	destroySandbox(t, id)
	runloopWaitRunning(t, ctx, id)

	cid := "cid-uc256-" + harness.UniqueName(sc, t)
	body := map[string]any{"command": "echo uc256; sleep 1", "command_id": cid}
	st1, b1 := fcDo(t, ctx, http.MethodPost, "", "/runloop/v1/devboxes/"+id+"/execute", body, nil)
	if st1 != http.StatusOK {
		t.Fatalf("first execute = %d, want 200; body=%s", st1, string(b1))
	}
	var e1 struct {
		ExecutionID string `json:"execution_id"`
	}
	fcDecode(t, b1, &e1)

	st2, b2 := fcDo(t, ctx, http.MethodPost, "", "/runloop/v1/devboxes/"+id+"/execute", body, nil)
	if st2 != http.StatusOK {
		t.Fatalf("replay execute = %d, want 200; body=%s", st2, string(b2))
	}
	var e2 struct {
		ExecutionID string `json:"execution_id"`
	}
	fcDecode(t, b2, &e2)
	if e1.ExecutionID == "" || e2.ExecutionID != e1.ExecutionID {
		t.Fatalf("repeated command_id gave execution %q then %q; want the same (durable dedup)", e1.ExecutionID, e2.ExecutionID)
	}
}

// UC-257 — Runloop create a devbox and exec returns command output.
func TestRunloopExecReturnsOutput(t *testing.T) {
	harness.Require(t, sc, "UC-257")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	id := runloopCreateDevbox(t, ctx)
	destroySandbox(t, id)
	runloopWaitRunning(t, ctx, id)

	st, body := fcDo(t, ctx, http.MethodPost, "", "/runloop/v1/devboxes/"+id+"/execute_sync", map[string]any{"command": "echo uc257-ok"}, nil)
	if st != http.StatusOK {
		t.Fatalf("execute_sync = %d, want 200; body=%s", st, string(body))
	}
	var det struct {
		Stdout string `json:"stdout"`
	}
	fcDecode(t, body, &det)
	if !strings.Contains(det.Stdout, "uc257-ok") {
		t.Fatalf("runloop exec stdout = %q, want uc257-ok", det.Stdout)
	}
}

// runloopCreateDevbox creates a default (ubuntu:22.04) devbox and returns its id.
func runloopCreateDevbox(t *testing.T, ctx context.Context) string {
	t.Helper()
	name := "uc-devbox-" + harness.UniqueName(sc, t)
	st, body := fcDo(t, ctx, http.MethodPost, "", "/runloop/v1/devboxes", map[string]any{"name": name}, nil)
	if st != http.StatusCreated && st != http.StatusOK {
		t.Fatalf("runloop create devbox = %d, want 201/200; body=%s", st, string(body))
	}
	var dv struct {
		ID string `json:"id"`
	}
	fcDecode(t, body, &dv)
	if dv.ID == "" {
		t.Fatalf("runloop create devbox returned no id: %s", string(body))
	}
	return dv.ID
}

// UC-258 — an exec on a stopped sandbox is refused (S12 running-state gate).
func TestExecOnStoppedSandboxRefused(t *testing.T) {
	harness.Require(t, sc, "UC-258")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if _, err := c.SDK().Stop(ctx, sb.ID); err != nil {
		t.Fatalf("stop sandbox: %v", err)
	}
	if _, err := sb.ExecCommand(ctx, "echo should-not-run"); err == nil {
		t.Fatalf("exec on a stopped sandbox returned no error, want a refusal (S12)")
	}
}

// UC-259 — a toolbox exec is routed to the owner node and runs in a cluster.
func TestExecRoutesToOwnerInCluster(t *testing.T) {
	harness.Require(t, sc, "UC-259")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	owner, err := c.OwnerNodeID(ctx, sb.ID)
	if err != nil || owner == "" {
		t.Fatalf("no placement owner for %s: %v", sb.ID, err)
	}
	res, err := sb.ExecCommand(ctx, "echo uc259-routed")
	if err != nil {
		t.Fatalf("exec (routed to owner %s): %v", owner, err)
	}
	if !strings.Contains(res.Stdout, "uc259-routed") {
		t.Fatalf("routed exec stdout = %q, want uc259-routed", res.Stdout)
	}
}
