package runloop

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression tests for the PR #641 review findings, one per finding, named
// for the invariant each one pins.

// Finding 1: a completed snapshot belongs to its owner's account, through
// every route and after its source devbox is gone.
func TestSnapshotsAreTenantScoped(t *testing.T) {
	env := newTestEnv(t)
	var devbox devboxView
	expectStatus(t, env.asTenant(t, "acct-a", http.MethodPost, "/create_and_await_running", `{}`, &devbox), http.StatusOK)
	var snap snapshotView
	expectStatus(t, env.asTenant(t, "acct-a", http.MethodPost, "/"+devbox.ID+"/snapshot_disk", `{"name":"private","metadata":{"secret":"tenant-a"}}`, &snap), http.StatusOK)

	check := func(stage string) {
		t.Helper()
		var listed listSnapshotsResponse
		expectStatus(t, env.asTenant(t, "acct-b", http.MethodGet, "/disk_snapshots", "", &listed), http.StatusOK)
		if len(listed.Snapshots) != 0 || listed.TotalCount == nil || *listed.TotalCount != 0 {
			t.Fatalf("%s: tenant B lists tenant A's snapshot: %+v", stage, listed)
		}
		for _, tc := range []struct {
			method, path, body string
			want               int
		}{
			{http.MethodGet, "/disk_snapshots/" + snap.ID + "/status", "", http.StatusNotFound},
			{http.MethodPost, "/disk_snapshots/" + snap.ID, `{"metadata":{"changed":"by-b"}}`, http.StatusNotFound},
			{http.MethodPost, "/create_and_await_running", fmt.Sprintf(`{"snapshot_id":%q}`, snap.ID), http.StatusBadRequest},
		} {
			expectStatus(t, env.asTenant(t, "acct-b", tc.method, tc.path, tc.body, nil), tc.want)
		}
		// A delete of a snapshot the caller cannot see is the idempotent
		// "already gone" answer — and must leave the owner's snapshot alone.
		expectStatus(t, env.asTenant(t, "acct-b", http.MethodPost, "/disk_snapshots/"+snap.ID+"/delete", "", nil), http.StatusOK)
		var status snapshotStatusView
		expectStatus(t, env.asTenant(t, "acct-a", http.MethodGet, "/disk_snapshots/"+snap.ID+"/status", "", &status), http.StatusOK)
		if status.Snapshot == nil || status.Snapshot.Metadata["secret"] != "tenant-a" || status.Snapshot.Metadata["changed"] != "" {
			t.Fatalf("%s: owner's snapshot changed: %+v", stage, status)
		}
		var mine listSnapshotsResponse
		expectStatus(t, env.asTenant(t, "acct-a", http.MethodGet, "/disk_snapshots", "", &mine), http.StatusOK)
		if len(mine.Snapshots) != 1 {
			t.Fatalf("%s: owner list = %+v", stage, mine)
		}
	}
	check("source live")
	// Ownership is on the snapshot row, not inferred from the source.
	expectStatus(t, env.asTenant(t, "acct-a", http.MethodPost, "/"+devbox.ID+"/shutdown", "", nil), http.StatusOK)
	check("source shut down")
	expectStatus(t, env.asTenant(t, "acct-a", http.MethodPost, "/create_and_await_running", fmt.Sprintf(`{"snapshot_id":%q}`, snap.ID), nil), http.StatusOK)
}

// Finding 2 (facade side): the ledger claim, not the toolbox's 201, picks
// the request that runs a command. A toolboxd that answers 201 to every
// racer still runs the command once.
func TestConcurrentDuplicateExecuteRunsOnce(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	env.toolbox.mu.Lock()
	env.toolbox.racyCreate = true
	env.toolbox.mu.Unlock()

	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo once","command_id":"race"}`, nil)
			codes <- rr.Code
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("duplicate execute status = %d", code)
		}
	}
	if got := env.toolbox.execCount(); got != 1 {
		t.Fatalf("command ran %d times for one command_id; want 1", got)
	}
}

// Finding 3: neither a sandboxd restart nor a result-cache eviction turns a
// retried command_id into a second run, and the replay still reports the
// real outcome.
func TestExecutionRetryNeverRerunsAfterRestartOrEviction(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	body := `{"command":"exit 3","command_id":"same-id"}`
	path := "/" + devbox.ID + "/execute"
	var first executionView
	expectStatus(t, env.do(t, http.MethodPost, path, body, &first), http.StatusOK)
	waitFor(t, "session cleanup", func() bool { return env.toolbox.sessionCount() == 0 })
	ref := mustRef(t, first.ExecutionID)
	waitFor(t, "ledger completion", func() bool {
		_, owed, ok := env.h.ledgerOutcome(context.Background(), devbox.ID, ref)
		return ok && !owed
	})

	// Restart: fresh facade state over the same store and toolbox.
	restarted := newHandlers(env.h.deps)
	if _, err := restarted.startExecution(context.Background(), devbox.ID, "exit 3", "", "same-id"); err != nil {
		t.Fatal(err)
	}
	state, err := restarted.executionState(context.Background(), devbox.ID, ref)
	if err != nil || !state.completed || state.exit != 3 {
		t.Fatalf("replay after restart = %+v, %v", state, err)
	}
	if !state.stderrCut() {
		t.Fatal("output lost with the cache must read as truncated, not empty")
	}

	// Eviction: 64 MiB of unrelated results push the original out.
	for i := range resultCacheBytes/maxCapturedStream + 1 {
		env.h.execs.record(&execResult{key: fmt.Sprintf("other/%d", i), stdout: strings.Repeat("x", maxCapturedStream)})
	}
	if _, ok := env.h.execs.result(resultKey(devbox.ID, ref.id())); ok {
		t.Fatal("the original result was not evicted")
	}
	var replay executionView
	expectStatus(t, env.do(t, http.MethodPost, path, body, &replay), http.StatusOK)
	if replay.ExecutionID != first.ExecutionID || replay.ExitStatus == nil || *replay.ExitStatus != 3 || replay.StderrTruncated == nil || !*replay.StderrTruncated {
		t.Fatalf("replay after eviction = %+v", replay)
	}
	if got := env.toolbox.execCount(); got != 1 {
		t.Fatalf("command ran %d times; want 1", got)
	}
}

// Finding 4: a local-image create in a cluster has no reservation, and must
// take the unreserved create under the devbox id instead of a reserved
// create against a reservation that does not exist.
func TestLocalImageCreateInClusterTakesUnreservedPath(t *testing.T) {
	env := newTestEnvWithConfig(t, func(cfg *config.Config) { cfg.EnableCluster = true })
	env.svc.AttachCluster(cluster.NewNoop("worker", "", ""))
	req := models.CreateSandboxRequest{Image: "aerolvm-build/review-local:latest"}
	r := httptest.NewRequest(http.MethodPost, devboxesPath, nil)
	decision, ok := clustercreate.Prepare(httptest.NewRecorder(), r, env.svc, req, writeErrorCode, clustercreate.PrepareOptions{PreferredSandboxID: "sb-0123456789abcdef"})
	if !ok || decision.ReservationID != "" {
		t.Fatalf("expected an unreserved local-image decision, got %+v %v", decision, ok)
	}
	sandbox, err := env.h.runCreate(context.Background(), req, decision.ReservationID, "sb-0123456789abcdef", devboxBlob{})
	if err != nil {
		t.Fatalf("unreserved local-image create: %v", err)
	}
	if sandbox.ID != "sb-0123456789abcdef" {
		t.Fatalf("devbox id = %q, want the retry-stable id", sandbox.ID)
	}
}

// nodeCluster is one node of an in-process test cluster: a Noop that knows
// the other nodes' facade handlers and forwards to them as ForwardHTTP
// would. Devbox ownership is left local (ErrUnknownSandbox).
type nodeCluster struct {
	*cluster.Noop
	mu    sync.Mutex
	peers map[string]http.Handler
	left  map[string]bool
}

func newNodeCluster(self string) *nodeCluster {
	return &nodeCluster{Noop: cluster.NewNoop(self, "", ""), peers: map[string]http.Handler{}, left: map[string]bool{}}
}

func (c *nodeCluster) OwnerOf(string) (cluster.OwnerInfo, error) {
	return cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
}

func (c *nodeCluster) Members() []cluster.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []cluster.Member{{NodeID: c.SelfNodeID(), Alive: true, Role: config.NodeRoleWorker}}
	for id := range c.peers {
		if !c.left[id] {
			out = append(out, cluster.Member{NodeID: id, Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://" + id})
		}
	}
	return out
}

func (c *nodeCluster) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	peer := c.peers[target.NodeID]
	c.mu.Unlock()
	r.Header.Set("X-Cluster-Forwarded", "1")
	peer.ServeHTTP(w, r)
}

// Findings 5 and 6: a snapshot is addressed through the node that holds it,
// so status, create-from-snapshot and delete work through any ingress, and
// keep working after the source devbox is shut down.
func TestSnapshotRoutesToItsNodeThroughIngress(t *testing.T) {
	worker, ingress := newTestEnv(t), newTestEnv(t)
	workerCluster, ingressCluster := newNodeCluster("worker"), newNodeCluster("ingress")
	ingressCluster.peers["worker"] = worker.handler
	workerCluster.peers["ingress"] = ingress.handler
	worker.svc.AttachCluster(workerCluster)
	ingress.svc.AttachCluster(ingressCluster)

	devbox := worker.mustCreate(t, "")
	var snap snapshotView
	expectStatus(t, worker.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk", `{}`, &snap), http.StatusOK)
	if node, ok := snapshotHomeNode(snap.ID); !ok || node != "worker" {
		t.Fatalf("snapshot id %q is not bound to its node", snap.ID)
	}
	statusPath := "/disk_snapshots/" + snap.ID + "/status"
	expectStatus(t, ingress.do(t, http.MethodGet, statusPath, nil, nil), http.StatusOK)

	// Finding 6: create from the snapshot through the ingress, source live.
	var restored devboxView
	expectStatus(t, ingress.do(t, http.MethodPost, "/create_and_await_running", fmt.Sprintf(`{"snapshot_id":%q}`, snap.ID), &restored), http.StatusOK)
	if _, err := worker.svc.GetSandbox(context.Background(), restored.ID); err != nil {
		t.Fatalf("restored devbox is not on the snapshot's node: %v", err)
	}

	// Finding 5: the source going away does not strand the snapshot.
	expectStatus(t, worker.do(t, http.MethodPost, "/"+devbox.ID+"/shutdown", nil, nil), http.StatusOK)
	expectStatus(t, ingress.do(t, http.MethodGet, statusPath, nil, nil), http.StatusOK)
	expectStatus(t, ingress.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID+"/delete", nil, nil), http.StatusOK)
	expectStatus(t, worker.do(t, http.MethodGet, statusPath, nil, nil), http.StatusNotFound)

	// A node that left took its snapshots: an explicit, non-retryable 503,
	// never a 404 or a delete that reports success.
	var other snapshotView
	second := worker.mustCreate(t, "")
	expectStatus(t, worker.do(t, http.MethodPost, "/"+second.ID+"/snapshot_disk", `{}`, &other), http.StatusOK)
	ingressCluster.mu.Lock()
	ingressCluster.left["worker"] = true
	ingressCluster.mu.Unlock()
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/disk_snapshots/" + other.ID + "/status", ""},
		{http.MethodPost, "/disk_snapshots/" + other.ID + "/delete", ""},
		{http.MethodPost, "/create_and_await_running", fmt.Sprintf(`{"snapshot_id":%q}`, other.ID)},
	} {
		rr := ingress.do(t, tc.method, tc.path, tc.body, nil)
		expectStatus(t, rr, http.StatusServiceUnavailable)
		if rr.Header().Get("x-should-retry") != "false" {
			t.Fatalf("%s %s: a departed node is not retryable", tc.method, tc.path)
		}
	}
	expectStatus(t, worker.do(t, http.MethodGet, "/disk_snapshots/"+other.ID+"/status", nil, nil), http.StatusOK)

	// A request forwarded to a node that is not the snapshot's is a loop.
	rr := ingress.do(t, http.MethodGet, "/disk_snapshots/"+snap.ID+"/status", nil, nil, "X-Cluster-Forwarded", "1")
	expectStatus(t, rr, http.StatusMisdirectedRequest)
}

// Finding 7: the caller's limit never sizes an allocation, and the list
// pages through the catalogue with starting_after.
func TestSnapshotListLimitIsClampedAndPages(t *testing.T) {
	env := newTestEnv(t)
	maxInt := int(^uint(0) >> 1)
	var page listSnapshotsResponse
	expectStatus(t, env.do(t, http.MethodGet, fmt.Sprintf("/disk_snapshots?limit=%d", maxInt), nil, &page), http.StatusOK)

	devbox := env.mustCreate(t, "")
	var ids []string
	for i := range 5 {
		var snap snapshotView
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk", fmt.Sprintf(`{"name":"s%d"}`, i), &snap), http.StatusOK)
		ids = append(ids, snap.ID)
	}
	var walked []string
	cursor := ""
	for range 10 {
		expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots?limit=2&starting_after="+cursor, nil, &page), http.StatusOK)
		if page.TotalCount == nil || *page.TotalCount != 5 {
			t.Fatalf("total_count = %v", page.TotalCount)
		}
		for _, s := range page.Snapshots {
			walked = append(walked, s.ID)
		}
		if !page.HasMore {
			break
		}
		cursor = page.Snapshots[len(page.Snapshots)-1].ID
	}
	sort.Strings(ids)
	sort.Strings(walked)
	if strings.Join(walked, ",") != strings.Join(ids, ",") {
		t.Fatalf("paging walked %v, want %v", walked, ids)
	}
	// A metadata filter that matches nothing still pages to an answer.
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots?metadata[none]=x", nil, &page), http.StatusOK)
	if len(page.Snapshots) != 0 || page.HasMore || *page.TotalCount != 0 {
		t.Fatalf("empty filter page = %+v", page)
	}
}

// Finding 8: a session whose delete failed is retried until it is gone,
// and work a dead process left behind is picked up on restart.
func TestSessionCleanupIsRetriedAndRecovered(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &watchMaxBackoff, 20*time.Millisecond)
	devbox := env.mustCreate(t, "")

	env.toolbox.failAlways("DELETE /process/session/"+plainSession(devbox.ID, "cleanup"), http.StatusServiceUnavailable)
	var done executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo done","command_id":"cleanup"}`, &done), http.StatusOK)
	if done.Status != execStatusCompleted {
		t.Fatalf("execution = %+v", done)
	}
	ref := mustRef(t, done.ExecutionID)
	time.Sleep(100 * time.Millisecond) // several failed deletes
	if env.toolbox.sessionCount() != 1 {
		t.Fatal("the session went away while its delete was failing")
	}
	if _, owed, ok := env.h.ledgerOutcome(context.Background(), devbox.ID, ref); !ok || !owed {
		t.Fatalf("the outcome must be stored with its cleanup still owed (ok=%v owed=%v)", ok, owed)
	}
	env.toolbox.clearFaults()
	waitFor(t, "the retried delete", func() bool { return env.toolbox.sessionCount() == 0 })
	waitFor(t, "the ledger to settle", func() bool {
		_, owed, ok := env.h.ledgerOutcome(context.Background(), devbox.ID, ref)
		return ok && !owed
	})

	// A process that died after submitting: its claim is pending and its
	// finished command's session is still live. A restart re-attaches.
	dead := execRef{session: plainSession(devbox.ID, "dead-process")}
	if _, _, err := env.h.claimLedger(context.Background(), ledgerKey(devbox.ID, dead)); err != nil {
		t.Fatal(err)
	}
	if _, err := env.h.createSession(context.Background(), devbox.ID, dead.session); err != nil {
		t.Fatal(err)
	}
	if _, err := env.h.sessionExec(context.Background(), devbox.ID, dead.session, "echo orphaned"); err != nil {
		t.Fatal(err)
	}
	// Rows recovery must skip: a named-shell claim and a malformed key.
	if _, _, err := env.h.claimLedger(context.Background(), namedLedgerKey(devbox.ID, "s", "k")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := env.h.claimLedger(context.Background(), "no-separator"); err != nil {
		t.Fatal(err)
	}
	restarted := newHandlers(env.h.deps)
	if err := restarted.recoverExecutions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := restarted.recoverExecutions(context.Background()); err != nil {
		t.Fatal("a second pass must be a no-op:", err)
	}
	waitFor(t, "the recovered session cleanup", func() bool { return env.toolbox.sessionCount() == 0 })
	waitFor(t, "the recovered ledger row", func() bool {
		outcome, owed, ok := restarted.ledgerOutcome(context.Background(), devbox.ID, dead)
		return ok && !owed && outcome.StdoutLen == int64(len("orphaned\n"))
	})
	restarted.recoverExecutionsInBackground() // latched: returns at once
}

// pagingCluster serves an authoritative placement index that honors the
// page token and limit, every placement owned by this node.
type pagingCluster struct {
	mockCluster
	ids []string
}

func (c *pagingCluster) PlacementPage(req cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	var page []cluster.Placement
	for _, id := range c.ids {
		if id > req.PageToken {
			page = append(page, cluster.Placement{SandboxID: id, OwnerNodeID: "self"})
		}
	}
	next := ""
	if len(page) > req.Limit {
		page = page[:req.Limit]
		next = page[len(page)-1].SandboxID
	}
	return cluster.PlacementPageResponse{Authoritative: true, Placements: page, NextPageToken: next}
}

// Finding 9: a status filter that empties a placement page must not end
// the SDK's paging early.
func TestFilteredClusterListAlwaysEndsInADevbox(t *testing.T) {
	env := newTestEnv(t)
	var ids []string
	for range 3 {
		ids = append(ids, env.mustCreate(t, "").ID)
	}
	sort.Strings(ids)
	// The first two by id are suspended; only the last is running.
	for _, id := range ids[:2] {
		expectStatus(t, env.do(t, http.MethodPost, "/"+id+"/suspend", nil, nil), http.StatusOK)
	}
	env.svc.AttachCluster(&pagingCluster{ids: ids})

	var page listDevboxesResponse
	expectStatus(t, env.do(t, http.MethodGet, "?limit=1&status=running", nil, &page), http.StatusOK)
	if len(page.Devboxes) != 1 || page.Devboxes[0].ID != ids[2] || page.HasMore {
		t.Fatalf("filtered page = %+v, want only %s", page, ids[2])
	}

	// No match within the scan budget: an explicit failure, never an empty
	// page that the SDK would read as the end.
	old := maxStatusScanPlacements
	maxStatusScanPlacements = 1
	t.Cleanup(func() { maxStatusScanPlacements = old })
	rr := env.do(t, http.MethodGet, "?limit=1&status=running", nil, nil)
	expectStatus(t, rr, http.StatusServiceUnavailable)
	if rr.Header().Get("x-should-retry") != "false" {
		t.Fatal("an exhausted scan budget is not retryable")
	}
}

// Finding 10: the home-directory cache is bounded, and an entry never
// answers for a later devbox that reuses the id.
func TestHomeCacheIsBoundedAndPerIncarnation(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, `{}`, "X-Request-Id", "home")
	for range 2 {
		if home, err := env.h.homeDir(context.Background(), devbox.ID); err != nil || home != "/home/user" {
			t.Fatalf("home = %q, %v", home, err)
		}
	}
	if env.toolbox.homeCalls != 1 {
		t.Fatalf("home lookups = %d, want 1 (cached)", env.toolbox.homeCalls)
	}
	// Native deletion (not the facade's shutdown), then a retried create
	// that lands on the same deterministic id with a different image home.
	if err := env.svc.DestroySandbox(context.Background(), devbox.ID); err != nil {
		t.Fatal(err)
	}
	env.toolbox.mu.Lock()
	env.toolbox.home = "/root"
	env.toolbox.mu.Unlock()
	again := env.mustCreate(t, `{}`, "X-Request-Id", "home")
	if again.ID != devbox.ID {
		t.Fatalf("recreate id = %s, want %s", again.ID, devbox.ID)
	}
	if home, err := env.h.homeDir(context.Background(), again.ID); err != nil || home != "/root" {
		t.Fatalf("new incarnation home = %q, %v", home, err)
	}

	cache := newHomeCache()
	for i := range maxHomeEntries + 10 {
		cache.put(fmt.Sprintf("sb-%d@1", i), "/h")
	}
	if cache.len() != maxHomeEntries {
		t.Fatalf("cache holds %d entries, cap %d", cache.len(), maxHomeEntries)
	}
	if _, ok := cache.get("sb-0@1"); ok {
		t.Fatal("the least recently used entry survived")
	}
	newest := fmt.Sprintf("sb-%d@1", maxHomeEntries+9)
	cache.put(newest, "/again")
	if home, _ := cache.get(newest); home != "/again" || cache.len() != maxHomeEntries {
		t.Fatal("put must update an existing entry in place")
	}
	cache.forget(fmt.Sprintf("sb-%d", maxHomeEntries+9))
	if _, ok := cache.get(newest); ok {
		t.Fatal("forget left the entry")
	}
}

// Finding 11: output past the per-stream cap is reported as truncated, in
// band and with real offsets, never streamed as if it were complete.
func TestStreamReportsTruncatedOutputWithRealOffsets(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var execution executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"lines 100000","command_id":"big"}`, &execution), http.StatusOK)
	full, _, _ := script("lines 100000")
	if len(full) <= maxCapturedStream {
		t.Fatalf("fixture output %d bytes does not exceed the cap", len(full))
	}
	if execution.StdoutTruncated == nil || !*execution.StdoutTruncated {
		t.Fatal("execution view must say stdout was truncated")
	}
	start := int64(len(full) - maxCapturedStream)
	path := "/" + devbox.ID + "/executions/" + execution.ExecutionID + "/stream_stdout_updates"

	chunks := readSSE(t, env.do(t, http.MethodGet, path, nil, nil).Body.String())
	if len(chunks) != 2 {
		t.Fatalf("chunks = %d, want a truncation notice and the retained tail", len(chunks))
	}
	if !strings.Contains(chunks[0].Output, fmt.Sprintf("%d earlier bytes of stdout were not kept", start)) || chunks[0].Offset != start {
		t.Fatalf("notice = %q @ %d", chunks[0].Output, chunks[0].Offset)
	}
	if chunks[1].Output != full[start:] || chunks[1].Offset != int64(len(full)) {
		t.Fatalf("tail = %d bytes @ %d", len(chunks[1].Output), chunks[1].Offset)
	}
	// Resuming inside the retained tail gets exactly the rest.
	resume := start + 10
	chunks = readSSE(t, env.do(t, http.MethodGet, fmt.Sprintf("%s?offset=%d", path, resume), nil, nil).Body.String())
	if len(chunks) != 1 || chunks[0].Output != full[resume:] {
		t.Fatalf("resume = %+v", len(chunks))
	}

	// Output too large for sandboxd to read at all.
	old := maxToolboxResponse
	maxToolboxResponse = 1024
	t.Cleanup(func() { maxToolboxResponse = old })
	var huge executionView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"lines 1000","command_id":"huge"}`, &huge), http.StatusOK)
	if huge.Status != execStatusCompleted || huge.StdoutTruncated == nil || !*huge.StdoutTruncated {
		t.Fatalf("oversized output view = %+v", huge)
	}
	chunks = readSSE(t, env.do(t, http.MethodGet, "/"+devbox.ID+"/executions/"+huge.ExecutionID+"/stream_stdout_updates", nil, nil).Body.String())
	if len(chunks) != 1 || !strings.Contains(chunks[0].Output, "too large to keep") {
		t.Fatalf("oversized stream = %+v", chunks)
	}
	if got := outputChunks("", -1, 5, "stdout"); got != nil {
		t.Fatalf("resume past an unknown-length notice = %+v", got)
	}
}
