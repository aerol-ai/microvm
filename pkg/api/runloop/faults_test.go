package runloop

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/clusterlist"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// execSQL runs raw SQL against the store to inject faults (a dropped
// table, a corrupt blob) that no API can produce.
func execSQL(t *testing.T, st *store.Store, query string) {
	t.Helper()
	field := reflect.ValueOf(st).Elem().FieldByName("db")
	db := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(*sql.DB)
	if _, err := db.ExecContext(context.Background(), query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func shorten(t *testing.T, target *time.Duration, d time.Duration) {
	t.Helper()
	old := *target
	*target = d
	t.Cleanup(func() { *target = old })
}

func expectError(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code < 400 {
		t.Fatalf("status = %d, want an error; body=%s", rr.Code, rr.Body.String())
	}
}

// TestCorruptDevboxStateFailsReads: an undecodable facade blob fails the
// request rather than answering with half a devbox.
func TestCorruptDevboxStateFailsReads(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, `{"name":"x"}`, "X-Request-Id", "corrupt")
	execSQL(t, env.store, `UPDATE sandbox_compat_state SET state_json = '{'`)
	base := "/" + devbox.ID
	expectError(t, env.do(t, http.MethodGet, base, nil, nil))
	expectError(t, env.do(t, http.MethodGet, "", nil, nil))
	expectError(t, env.do(t, http.MethodPost, base, `{"name":"y"}`, nil))
	expectError(t, env.do(t, http.MethodPost, base+"/suspend", nil, nil))
	expectError(t, env.do(t, http.MethodPost, base+"/resume", nil, nil))
	expectError(t, env.do(t, http.MethodPost, base+"/shutdown", nil, nil))
	expectError(t, env.do(t, http.MethodPost, base+"/wait_for_status", `{"statuses":["running"]}`, nil))
	// A retried create of this devbox answers from the row, so it too fails.
	expectError(t, env.do(t, http.MethodPost, "", `{"name":"x"}`, nil, "X-Request-Id", "corrupt"))
	env.mustCreate(t, "", "X-Request-Id", "unrelated")
}

// TestFacadeStateWriteFailureRollsBackCreate: the facade blob is part of
// the create, so failing to write it removes the sandbox.
func TestFacadeStateWriteFailureRollsBackCreate(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	execSQL(t, env.store, `DROP TABLE sandbox_compat_state`)
	expectError(t, env.do(t, http.MethodGet, "", nil, nil))
	expectError(t, env.do(t, http.MethodPost, "/"+devbox.ID, `{"name":"y"}`, nil))
	rr := env.do(t, http.MethodPost, "", "", nil)
	expectError(t, rr)
	sandboxes, err := env.store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sandboxes) != 1 {
		t.Fatalf("rolled-back create left %d sandboxes", len(sandboxes))
	}
}

func TestClosedStoreFailsEveryEntryPoint(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	_ = env.store.Close()
	base := "/" + devbox.ID
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, base, ""},
		{http.MethodGet, "", ""},
		{http.MethodPost, "", `{}`},
		{http.MethodPost, base + "/shutdown", ""},
		{http.MethodPost, base + "/suspend", ""},
		{http.MethodPost, base + "/keep_alive", ""},
		{http.MethodPost, base, `{"metadata":{}}`},
		{http.MethodGet, base + "/executions/rlx-00", ""},
		{http.MethodPost, base + "/snapshot_disk", `{}`},
		{http.MethodGet, "/disk_snapshots", ""},
		{http.MethodGet, "/disk_snapshots/snp-sb-00.00/status", ""},
		{http.MethodPost, "/disk_snapshots/x/delete", ""},
		{http.MethodPost, "/disk_snapshots/x", `{}`},
	} {
		expectError(t, env.do(t, tc.method, tc.path, tc.body, nil))
	}
}

func TestRuntimeFaultsOnLifecycle(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	base := "/" + devbox.ID
	env.runtime.errStop = errors.New("stop failed")
	expectError(t, env.do(t, http.MethodPost, base+"/suspend", nil, nil))
	env.runtime.errStop = nil
	expectStatus(t, env.do(t, http.MethodPost, base+"/suspend", nil, nil), http.StatusOK)
	env.runtime.errStart = errors.New("start failed")
	expectError(t, env.do(t, http.MethodPost, base+"/resume", nil, nil))
	env.runtime.errStart = nil

	// A devbox in a failed state can be neither suspended nor resumed.
	execSQL(t, env.store, `UPDATE sandboxes SET status = 'error'`)
	expectStatus(t, env.do(t, http.MethodPost, base+"/suspend", nil, nil), http.StatusConflict)
	expectStatus(t, env.do(t, http.MethodPost, base+"/resume", nil, nil), http.StatusConflict)
	var view devboxView
	expectStatus(t, env.do(t, http.MethodGet, base, nil, &view), http.StatusOK)
	if view.Status != statusFailure || view.FailureReason == nil {
		t.Fatalf("failed devbox = %+v", view)
	}
}

func TestSnapshotStoreFaults(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var snap snapshotView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk", `{"name":"a"}`, &snap), http.StatusOK)

	// Undecodable Runloop attributes fail the reads that need them.
	execSQL(t, env.store, `UPDATE snapshot_aliases SET state_json = '{'`)
	expectError(t, env.do(t, http.MethodGet, "/disk_snapshots/"+snap.ID+"/status", nil, nil))
	expectError(t, env.do(t, http.MethodGet, "/disk_snapshots", nil, nil))
	expectError(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID, `{"name":"b"}`, nil))

	// Without the alias table, taking a snapshot rolls its commit back.
	execSQL(t, env.store, `DROP TABLE snapshot_aliases`)
	expectError(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk", `{"name":"c"}`, nil, "X-Request-Id", "c"))
	snapshots, err := env.store.ListSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("failed snapshot left %d snapshots", len(snapshots))
	}
	expectError(t, env.do(t, http.MethodGet, "/disk_snapshots", nil, nil))
	expectError(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID+"/delete", nil, nil))
	expectError(t, env.do(t, http.MethodPost, "", `{"snapshot_id":"`+snap.ID+`"}`, nil))
}

func TestSnapshotListPagingAndUpdateFields(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	for _, key := range []string{"p1", "p2"} {
		expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk", `{}`, nil, "X-Request-Id", key), http.StatusOK)
	}
	var page listSnapshotsResponse
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots?limit=1", nil, &page), http.StatusOK)
	if len(page.Snapshots) != 1 || !page.HasMore {
		t.Fatalf("page = %+v", page)
	}
	var updated snapshotView
	expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+page.Snapshots[0].ID, `{"commit_message":" msg "}`, &updated), http.StatusOK)
	if updated.CommitMessage == nil || *updated.CommitMessage != "msg" {
		t.Fatalf("commit message = %v", updated.CommitMessage)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+page.Snapshots[0].ID, `{`, nil), http.StatusBadRequest)
}

func TestSnapshotRequestCancelled(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	env.runtime.blockSnapshot = make(chan struct{})
	defer close(env.runtime.blockSnapshot)
	for _, action := range []string{"snapshot_disk", "snapshot_disk_async"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		req := httptest.NewRequest(http.MethodPost, devboxesPath+"/"+devbox.ID+"/"+action, strings.NewReader(`{}`)).WithContext(ctx)
		rr := httptest.NewRecorder()
		old := snapshotHold
		snapshotHold = time.Minute
		env.handler.ServeHTTP(rr, req)
		snapshotHold = old
		cancel()
		if rr.Body.Len() != 0 {
			t.Fatalf("%s wrote after the client left: %s", action, rr.Body.String())
		}
	}
	expectStatus(t, env.do(t, http.MethodPost, "/sb-missing/snapshot_disk_async", `{}`, nil), http.StatusNotFound)
}

func TestCreateRequestCancelledKeepsCreating(t *testing.T) {
	env := newTestEnv(t)
	env.runtime.blockCreate = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, devboxesPath, strings.NewReader(`{}`)).WithContext(ctx)
	req.Header.Set("X-Request-Id", "gone")
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Body.Len() != 0 {
		t.Fatalf("create wrote after the client left: %s", rr.Body.String())
	}
	// The create carries on detached; a retry joins and sees it finish.
	close(env.runtime.blockCreate)
	env.mustCreate(t, `{}`, "X-Request-Id", "gone")
	if env.runtime.creates != 1 {
		t.Fatalf("creates = %d, want 1", env.runtime.creates)
	}
}

// placementFailCluster refuses every placement, so Prepare answers itself.
type placementFailCluster struct{ mockCluster }

func (placementFailCluster) SelectPlacementForCreate(capacity.Request, string, int) (cluster.PlacementTarget, []string, error) {
	return cluster.PlacementTarget{}, nil, cluster.ErrNoPlacementTarget
}

func TestCreatePlacementFailure(t *testing.T) {
	env := newTestEnv(t)
	env.svc.AttachCluster(&placementFailCluster{})
	expectStatus(t, env.do(t, http.MethodPost, "", `{}`, nil), http.StatusServiceUnavailable)
	if env.runtime.creates != 0 {
		t.Fatal("refused placement still created")
	}
}

func TestRunCreateAnswersExistingRow(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	got, err := env.h.runCreate(context.Background(), models.CreateSandboxRequest{Image: defaultImage}, "", devbox.ID, devboxBlob{})
	if err != nil || got.ID != devbox.ID || env.runtime.creates != 1 {
		t.Fatalf("runCreate on existing id = %v, %v (creates %d)", got, err, env.runtime.creates)
	}
	_ = env.store.Close()
	if _, err := env.h.runCreate(context.Background(), models.CreateSandboxRequest{}, "", "sb-x", devboxBlob{}); err == nil {
		t.Fatal("runCreate ignored a store failure")
	}
}

func TestListDevboxesClusterEdges(t *testing.T) {
	env := newTestEnv(t)
	env.mustCreate(t, "")
	// A placement owned by a node nobody knows marks the page partial.
	env.svc.AttachCluster(&mockCluster{page: cluster.PlacementPageResponse{
		Authoritative: true,
		Placements:    []cluster.Placement{{SandboxID: "sb-ghost", OwnerNodeID: "ghost"}},
	}})
	rr := env.do(t, http.MethodGet, "", nil, nil)
	expectStatus(t, rr, http.StatusOK)
	if rr.Header().Get(clusterlist.HeaderPartial) != "true" {
		t.Fatalf("partial header = %q", rr.Header().Get(clusterlist.HeaderPartial))
	}
	// A cold index on a fleet too large to fan out is not answerable.
	big := &bigFleetCluster{}
	env.svc.AttachCluster(big)
	expectStatus(t, env.do(t, http.MethodGet, "", nil, nil), http.StatusServiceUnavailable)
	// A reachable-looking peer that fails is reported, not fatal.
	env.svc.AttachCluster(&peerFleetCluster{})
	expectStatus(t, env.do(t, http.MethodGet, "", nil, nil), http.StatusOK)
	if (&handlers{deps: Deps{Service: env.svc}}).clusterClient() == nil {
		t.Fatal("a real cluster client was treated as single-node")
	}
}

type bigFleetCluster struct{ mockCluster }

func (bigFleetCluster) Members() []cluster.Member {
	members := make([]cluster.Member, 300)
	for i := range members {
		members[i] = cluster.Member{NodeID: "n" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + time.Duration(i).String(), Alive: true, Role: config.NodeRoleWorker}
	}
	return members
}

type peerFleetCluster struct{ mockCluster }

func (peerFleetCluster) Members() []cluster.Member {
	return []cluster.Member{{NodeID: "peer", Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://127.0.0.1:1"}}
}

func TestFlightTrackerSweepsOldFailures(t *testing.T) {
	tr := newFlightTracker[string, int]()
	f, _ := tr.claim("a", "meta")
	tr.finish(f, 0, errors.New("boom"))
	f.finished = time.Now().Add(-2 * failedFlightRetention)
	if _, ok := tr.get("a"); !ok {
		t.Fatal("failed flight not retained")
	}
	tr.claim("b", "meta")
	if _, ok := tr.get("a"); ok {
		t.Fatal("expired failed flight not swept")
	}
	// A retry after a failure starts a new attempt.
	g, _ := tr.claim("c", "m")
	tr.finish(g, 0, errors.New("boom"))
	if again, started := tr.claim("c", "m"); !started || again == g {
		t.Fatal("retry after failure did not start fresh")
	}
}
