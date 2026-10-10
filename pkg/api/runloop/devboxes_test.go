package runloop

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreateDevboxTranslatesRequest(t *testing.T) {
	env := newTestEnv(t)
	view := env.mustCreate(t, map[string]any{
		"name":                  "agent-box",
		"blueprint_name":        "python",
		"metadata":              map[string]string{"team": "sdk"},
		"environment_variables": map[string]string{"FOO": "bar"},
		"launch_parameters": map[string]any{
			"resource_size_request": "MEDIUM",
			"after_idle":            map[string]any{"idle_time_seconds": 300, "on_idle": "suspend"},
			"architecture":          "x86_64",
			"available_ports":       []int{8080},
		},
	})
	if view.Name == nil || *view.Name != "agent-box" {
		t.Fatalf("name = %v", view.Name)
	}
	if view.BlueprintID == nil || *view.BlueprintID != "python" {
		t.Fatalf("blueprint_id = %v", view.BlueprintID)
	}
	if view.Metadata["team"] != "sdk" {
		t.Fatalf("metadata = %v", view.Metadata)
	}
	if view.LaunchParameters.ResourceSizeRequest == nil || *view.LaunchParameters.ResourceSizeRequest != "MEDIUM" {
		t.Fatalf("launch_parameters not echoed: %+v", view.LaunchParameters)
	}
	if view.EndTimeMs != nil || view.Capabilities == nil || view.StateTransitions == nil || view.CreateTimeMs == 0 {
		t.Fatalf("required DevboxView keys missing: %+v", view)
	}

	sandbox, err := env.svc.GetSandbox(context.Background(), view.ID)
	if err != nil {
		t.Fatalf("GetSandbox: %v", err)
	}
	if sandbox.Image != "python:3.12" {
		t.Fatalf("image = %q, want python:3.12", sandbox.Image)
	}
	if sandbox.CPU != 2 || sandbox.MemoryMB != 4096 || sandbox.DiskGB != 8 {
		t.Fatalf("resources = %v cpu %d MiB %d GiB", sandbox.CPU, sandbox.MemoryMB, sandbox.DiskGB)
	}
	if sandbox.Lifecycle.StopIfIdleFor != 300*time.Second || sandbox.Lifecycle.DestroyAtAge != 0 {
		t.Fatalf("lifecycle = %+v", sandbox.Lifecycle)
	}
	if env.runtime.lastReq.Env["FOO"] != "bar" {
		t.Fatalf("env = %v", env.runtime.lastReq.Env)
	}

	var got devboxView
	expectStatus(t, env.do(t, http.MethodGet, "/"+view.ID, nil, &got), http.StatusOK)
	if got.ID != view.ID || got.Status != statusRunning || got.Name == nil || *got.Name != "agent-box" {
		t.Fatalf("retrieve = %+v", got)
	}
}

func TestCreateDevboxDefaultsToKeepAliveTTL(t *testing.T) {
	env := newTestEnv(t)
	view := env.mustCreate(t, "")
	sandbox, err := env.store.Get(context.Background(), view.ID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if sandbox.Image != defaultImage {
		t.Fatalf("image = %q", sandbox.Image)
	}
	if sandbox.Lifecycle.DestroyAtAge != time.Hour {
		t.Fatalf("DestroyAtAge = %v, want 1h", sandbox.Lifecycle.DestroyAtAge)
	}
}

func TestCreateDevboxRetryIsIdempotent(t *testing.T) {
	env := newTestEnv(t)
	body := `{"name":"same"}`
	first := env.mustCreate(t, body, "X-Request-Id", "stainless-node-retry-1")
	second := env.mustCreate(t, body, "X-Request-Id", "stainless-node-retry-1")
	if first.ID != second.ID {
		t.Fatalf("retry created a second devbox: %s vs %s", first.ID, second.ID)
	}
	if env.runtime.creates != 1 {
		t.Fatalf("runtime creates = %d, want 1", env.runtime.creates)
	}
	// Same request id, different body: a distinct create.
	third := env.mustCreate(t, `{"name":"other"}`, "X-Request-Id", "stainless-node-retry-1")
	if third.ID == first.ID {
		t.Fatal("a different body reused the devbox")
	}
}

func TestCreateDevboxRejectsUnsupportedFields(t *testing.T) {
	env := newTestEnv(t)
	rr := env.do(t, http.MethodPost, "", `{"entrypoint":"python app.py","secrets":{"A":"b"},"launch_parameters":{"launch_commands":["ls"]}}`, nil)
	expectStatus(t, rr, http.StatusNotImplemented)
	if rr.Header().Get("x-should-retry") != "false" {
		t.Fatal("501 must carry x-should-retry: false")
	}
	for _, field := range []string{"entrypoint", "secrets", "launch_commands"} {
		if !strings.Contains(rr.Body.String(), field) {
			t.Fatalf("error does not name %s: %s", field, rr.Body.String())
		}
	}
	if env.runtime.creates != 0 {
		t.Fatal("refused create reached the runtime")
	}
}

func TestCreateDevboxValidation(t *testing.T) {
	env := newTestEnv(t)
	cases := map[string]string{
		"unknown blueprint":     `{"blueprint_name":"nope"}`,
		"two sources":           `{"blueprint_name":"python","snapshot_id":"snp-x"}`,
		"unknown snapshot":      `{"snapshot_id":"snx-bm9wZQ"}`,
		"bad size":              `{"launch_parameters":{"resource_size_request":"HUGE"}}`,
		"bad keep alive":        `{"launch_parameters":{"keep_alive_time_seconds":999999}}`,
		"bad on_idle":           `{"launch_parameters":{"after_idle":{"idle_time_seconds":5,"on_idle":"nap"}}}`,
		"invalid json":          `{`,
		"custom without values": `{"launch_parameters":{"resource_size_request":"CUSTOM_SIZE"}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			expectStatus(t, env.do(t, http.MethodPost, "", body, nil), http.StatusBadRequest)
		})
	}
}

func TestCreateHoldReturnsProvisioningAndWaitTracksIt(t *testing.T) {
	env := newTestEnv(t)
	old := createHold
	createHold = 50 * time.Millisecond
	t.Cleanup(func() { createHold = old })
	env.runtime.blockCreate = make(chan struct{})

	var view devboxView
	expectStatus(t, env.do(t, http.MethodPost, "", `{"name":"slow"}`, &view, "X-Request-Id", "req-slow"), http.StatusOK)
	if view.Status != statusProvisioning || view.ID == "" {
		t.Fatalf("held create = %+v, want provisioning", view)
	}
	// A retry joins the in-flight create rather than starting another.
	var again devboxView
	expectStatus(t, env.do(t, http.MethodPost, "", `{"name":"slow"}`, &again, "X-Request-Id", "req-slow"), http.StatusOK)
	if again.ID != view.ID {
		t.Fatalf("retry id %s != %s", again.ID, view.ID)
	}
	// Retrieve works before the row exists.
	var got devboxView
	expectStatus(t, env.do(t, http.MethodGet, "/"+view.ID, nil, &got), http.StatusOK)
	if got.Status != statusProvisioning {
		t.Fatalf("retrieve during create = %q", got.Status)
	}
	// Still provisioning: the long-poll times out with 408.
	rr := env.do(t, http.MethodPost, "/"+view.ID+"/wait_for_status", `{"statuses":["running"],"timeout_seconds":0.05}`, nil)
	expectStatus(t, rr, http.StatusRequestTimeout)
	if rr.Header().Get("retry-after-ms") == "" {
		t.Fatal("408 should carry retry-after-ms")
	}

	close(env.runtime.blockCreate)
	var done devboxView
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/wait_for_status", `{"statuses":["running","failure","shutdown"],"timeout_seconds":5}`, &done), http.StatusOK)
	if done.Status != statusRunning || done.Name == nil || *done.Name != "slow" {
		t.Fatalf("after create = %+v", done)
	}
	if env.runtime.creates != 1 {
		t.Fatalf("runtime creates = %d, want 1", env.runtime.creates)
	}
}

func TestCreateFailureAfterHoldReportsFailure(t *testing.T) {
	env := newTestEnv(t)
	old := createHold
	createHold = 20 * time.Millisecond
	t.Cleanup(func() { createHold = old })
	env.runtime.blockCreate = make(chan struct{})
	env.runtime.errCreate = errors.New("image pull failed")

	var view devboxView
	expectStatus(t, env.do(t, http.MethodPost, "", "", &view), http.StatusOK)
	close(env.runtime.blockCreate)
	var done devboxView
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/wait_for_status", `{"statuses":["running"],"timeout_seconds":5}`, &done), http.StatusOK)
	if done.Status != statusFailure || done.FailureReason == nil {
		t.Fatalf("failed create = %+v", done)
	}
}

func TestCreateFailureInsideHoldReturnsError(t *testing.T) {
	env := newTestEnv(t)
	env.runtime.errCreate = errors.New("image pull failed")
	rr := env.do(t, http.MethodPost, "", "", nil)
	if rr.Code < 400 {
		t.Fatalf("status = %d, want an error", rr.Code)
	}
}

func TestListDevboxesPaginates(t *testing.T) {
	env := newTestEnv(t)
	ids := map[string]bool{}
	for i := 0; i < 3; i++ {
		ids[env.mustCreate(t, "").ID] = true
	}
	var page listDevboxesResponse
	expectStatus(t, env.do(t, http.MethodGet, "?limit=2", nil, &page), http.StatusOK)
	if len(page.Devboxes) != 2 || !page.HasMore || page.TotalCount == nil || *page.TotalCount != 3 {
		t.Fatalf("page 1 = %+v", page)
	}
	var next listDevboxesResponse
	expectStatus(t, env.do(t, http.MethodGet, "?limit=2&starting_after="+page.Devboxes[1].ID, nil, &next), http.StatusOK)
	if len(next.Devboxes) != 1 || next.HasMore {
		t.Fatalf("page 2 = %+v", next)
	}
	seen := map[string]bool{}
	for _, v := range append(page.Devboxes, next.Devboxes...) {
		seen[v.ID] = true
	}
	for id := range ids {
		if !seen[id] {
			t.Fatalf("devbox %s missing from pages", id)
		}
	}

	var filtered listDevboxesResponse
	expectStatus(t, env.do(t, http.MethodGet, "?status=suspended&include_total_count=false", nil, &filtered), http.StatusOK)
	if len(filtered.Devboxes) != 0 || filtered.TotalCount != nil {
		t.Fatalf("status filter = %+v", filtered)
	}
	expectStatus(t, env.do(t, http.MethodGet, "?limit=0", nil, nil), http.StatusBadRequest)
}

func TestListDevboxesPeerHopReturnsBareArray(t *testing.T) {
	env := newTestEnv(t)
	keep := env.mustCreate(t, "")
	env.mustCreate(t, "")
	var items []devboxView
	expectStatus(t, env.do(t, http.MethodGet, "?ids="+keep.ID, nil, &items, "X-Cluster-Forwarded", "1"), http.StatusOK)
	if len(items) != 1 || items[0].ID != keep.ID {
		t.Fatalf("peer list = %+v", items)
	}
}

func TestUpdateDevbox(t *testing.T) {
	env := newTestEnv(t)
	view := env.mustCreate(t, `{"name":"before","metadata":{"a":"1"}}`)
	var updated devboxView
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID, `{"name":"after","metadata":{"b":"2"}}`, &updated), http.StatusOK)
	if updated.Name == nil || *updated.Name != "after" || updated.Metadata["b"] != "2" || updated.Metadata["a"] != "" {
		t.Fatalf("update = %+v", updated)
	}
	// Omitted fields stay; {} clears metadata.
	var cleared devboxView
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID, `{"metadata":{}}`, &cleared), http.StatusOK)
	if cleared.Name == nil || *cleared.Name != "after" || len(cleared.Metadata) != 0 {
		t.Fatalf("partial update = %+v", cleared)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/sb-missing", `{}`, nil), http.StatusNotFound)
}

func TestSuspendResumeKeepAlive(t *testing.T) {
	env := newTestEnv(t)
	view := env.mustCreate(t, "")
	var got devboxView
	for i := 0; i < 2; i++ { // the second suspend is a no-op
		expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/suspend", nil, &got), http.StatusOK)
		if got.Status != statusSuspended {
			t.Fatalf("suspend #%d = %q", i, got.Status)
		}
	}
	// A suspended devbox cannot reach running on its own: the wait answers
	// at once instead of holding.
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/wait_for_status", `{"statuses":["running"]}`, &got), http.StatusOK)
	if got.Status != statusSuspended {
		t.Fatalf("wait = %q", got.Status)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/execute", `{"command":"echo hi","command_id":"c1"}`, nil), http.StatusConflict)
	for i := 0; i < 2; i++ {
		expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/resume", nil, &got), http.StatusOK)
		if got.Status != statusRunning {
			t.Fatalf("resume #%d = %q", i, got.Status)
		}
	}
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/keep_alive", nil, nil), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodPost, "/sb-missing/keep_alive", nil, nil), http.StatusNotFound)
	expectStatus(t, env.do(t, http.MethodPost, "/sb-missing/suspend", nil, nil), http.StatusNotFound)
	expectStatus(t, env.do(t, http.MethodPost, "/sb-missing/resume", nil, nil), http.StatusNotFound)
}

func TestShutdownIsTerminalAndIdempotent(t *testing.T) {
	env := newTestEnv(t)
	view := env.mustCreate(t, `{"name":"bye"}`)
	var got devboxView
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/shutdown?force=true", nil, &got), http.StatusOK)
	if got.Status != statusShutdown || got.EndTimeMs == nil || got.ShutdownReason == nil || got.Name == nil {
		t.Fatalf("shutdown = %+v", got)
	}
	if _, err := env.store.Get(context.Background(), view.ID); err == nil {
		t.Fatal("shutdown left the sandbox row behind")
	}
	// A retried shutdown and later reads see the terminal view.
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/shutdown", nil, &got), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodGet, "/"+view.ID, nil, &got), http.StatusOK)
	if got.Status != statusShutdown {
		t.Fatalf("after shutdown = %q", got.Status)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/sb-missing/shutdown", nil, nil), http.StatusNotFound)
}

func TestWaitForDevboxStatus(t *testing.T) {
	env := newTestEnv(t)
	view := env.mustCreate(t, "")
	var got devboxView
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/wait_for_status", `{"statuses":["running"],"timeout_seconds":29.98}`, &got), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/wait_for_status", `{}`, nil), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, "/"+view.ID+"/wait_for_status", `{`, nil), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, "/sb-missing/wait_for_status", `{"statuses":["running"]}`, nil), http.StatusNotFound)
}

func TestRouting(t *testing.T) {
	env := newTestEnv(t)
	view := env.mustCreate(t, "")
	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodDelete, "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/create_and_await_running", http.StatusMethodNotAllowed},
		{http.MethodGet, "/evictions/watch", http.StatusNotFound},
		{http.MethodGet, "/" + view.ID + "/nope", http.StatusNotFound},
		{http.MethodGet, "/" + view.ID + "/shutdown", http.StatusMethodNotAllowed},
		{http.MethodPost, "/" + view.ID + "/logs", http.StatusMethodNotAllowed},
		{http.MethodGet, "/" + view.ID + "/a/b", http.StatusNotFound},
		{http.MethodDelete, "/" + view.ID, http.StatusMethodNotAllowed},
		{http.MethodGet, "/" + view.ID + "/executions", http.StatusNotFound},
		{http.MethodGet, "/" + view.ID + "/executions/x/y/z", http.StatusNotFound},
		{http.MethodGet, "/" + view.ID + "/executions/rlx-00/nope", http.StatusNotFound},
		{http.MethodGet, "/disk_snapshots/x/nope", http.StatusNotFound},
		{http.MethodDelete, "/disk_snapshots", http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		expectStatus(t, env.do(t, tc.method, tc.path, nil, nil), tc.want)
	}
	for _, action := range []string{"enable_tunnel", "remove_tunnel", "create_ssh_key", "create_pty_tunnel"} {
		rr := env.do(t, http.MethodPost, "/"+view.ID+"/"+action, nil, nil)
		expectStatus(t, rr, http.StatusNotImplemented)
		if rr.Header().Get("x-should-retry") != "false" {
			t.Fatalf("%s: 501 without x-should-retry: false", action)
		}
	}
	expectStatus(t, env.do(t, http.MethodGet, "/"+view.ID+"/usage", nil, nil), http.StatusNotImplemented)
}

func TestDevboxStatusMapping(t *testing.T) {
	cases := map[models.SandboxStatus]string{
		models.SandboxStatusCreating:        statusProvisioning,
		models.SandboxStatusAwaitingRuntime: statusProvisioning,
		models.SandboxStatusStarted:         statusRunning,
		models.SandboxStatusStopped:         statusSuspended,
		models.SandboxStatusPassivated:      statusSuspended,
		models.SandboxStatusDestroyed:       statusShutdown,
		models.SandboxStatusError:           statusFailure,
		models.SandboxStatusPassivateFailed: statusFailure,
	}
	for native, want := range cases {
		if got := devboxStatus(native); got != want {
			t.Fatalf("devboxStatus(%s) = %s, want %s", native, got, want)
		}
	}
}

func TestTombstonesEvict(t *testing.T) {
	ts := newTombstones()
	for i := 0; i < maxTombstones+5; i++ {
		ts.put(strings.Repeat("x", i%7)+string(rune('a'+i%26))+time.Now().String()+string(rune(i)), "", devboxView{})
	}
	if len(ts.views) > maxTombstones {
		t.Fatalf("tombstones grew to %d", len(ts.views))
	}
	ts.put("old", "", devboxView{ID: "old"})
	ts.views["old"] = tombstone{view: devboxView{ID: "old"}, at: time.Now().Add(-2 * tombstoneTTL)}
	if _, ok := ts.get(context.Background(), "old"); ok {
		t.Fatal("expired tombstone answered")
	}
}
