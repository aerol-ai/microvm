package runloop

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// failWrites makes one statement kind on one table fail until the returned
// func runs.
func failWrites(t *testing.T, st *store.Store, name, event string) (clear func()) {
	t.Helper()
	execSQL(t, st, fmt.Sprintf("CREATE TRIGGER %s BEFORE %s BEGIN SELECT RAISE(ABORT, 'injected fault'); END", name, event))
	return func() { execSQL(t, st, "DROP TRIGGER IF EXISTS "+name) }
}

func (e *testEnv) snapshotCommits() int {
	e.runtime.mu.Lock()
	defer e.runtime.mu.Unlock()
	return e.runtime.imageSeq
}

// A failed attribute write leaves the snapshot exactly as it was, and a
// failed delete leaves it usable; a retry of either then succeeds.
func TestSnapshotWriteFailuresChangeNothing(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var snap snapshotView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk", `{"name":"a","metadata":{"k":"v"}}`, &snap), http.StatusOK)
	status := func() snapshotStatusView {
		t.Helper()
		var view snapshotStatusView
		expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/"+snap.ID+"/status", nil, &view), http.StatusOK)
		return view
	}

	clear := failWrites(t, env.store, "fault_alias_update", "UPDATE ON snapshot_aliases")
	expectError(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID, `{"name":"b","metadata":{"k":"changed"}}`, nil))
	if got := status(); got.Snapshot == nil || got.Snapshot.Metadata["k"] != "v" || got.Snapshot.Name == nil || *got.Snapshot.Name != "a" {
		t.Fatalf("a failed update changed the snapshot: %+v", got.Snapshot)
	}
	clear()
	expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID, `{"metadata":{"k":"changed"}}`, nil), http.StatusOK)

	clear = failWrites(t, env.store, "fault_snapshot_delete", "DELETE ON sandbox_snapshots")
	expectError(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID+"/delete", nil, nil))
	if got := status(); got.Status != "complete" || got.Snapshot.Metadata["k"] != "changed" {
		t.Fatalf("a failed delete damaged the snapshot: %+v", got)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/create_and_await_running", fmt.Sprintf(`{"snapshot_id":%q}`, snap.ID), nil), http.StatusOK)
	clear()
	expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID+"/delete", nil, nil), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/"+snap.ID+"/status", nil, nil), http.StatusNotFound)
}

// The alias is part of the snapshot, so a failed alias write fails the
// request. When the rollback of the commit fails as well, the retry adopts
// the committed snapshot instead of committing the devbox a second time.
func TestSnapshotRetryAfterAFailedRollbackAdoptsTheCommit(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	clearAlias := failWrites(t, env.store, "fault_alias_insert", "INSERT ON snapshot_aliases")
	clearDelete := failWrites(t, env.store, "fault_snapshot_delete", "DELETE ON sandbox_snapshots")
	path := "/" + devbox.ID + "/snapshot_disk"
	expectError(t, env.do(t, http.MethodPost, path, `{"name":"rb"}`, nil, "X-Request-Id", "rb"))
	if got := env.snapshotCommits(); got != 1 {
		t.Fatalf("commits = %d", got)
	}
	clearAlias()
	clearDelete()

	var snap snapshotView
	expectStatus(t, env.do(t, http.MethodPost, path, `{"name":"rb"}`, &snap, "X-Request-Id", "rb"), http.StatusOK)
	if snap.Name == nil || *snap.Name != "rb" {
		t.Fatalf("retried snapshot = %+v", snap)
	}
	if got := env.snapshotCommits(); got != 1 {
		t.Fatalf("the retry committed the devbox again: %d commits", got)
	}
}

// Duplicate snapshot requests in flight at once (an SDK retrying a slow
// snapshot_disk_async) join one commit and all answer with its id.
func TestConcurrentDuplicateSnapshotCommitsOnce(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &snapshotHold, 10*time.Millisecond)
	devbox := env.mustCreate(t, "")
	env.runtime.blockSnapshot = make(chan struct{})

	ids := make(chan string, 4)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var view snapshotView
			rr := env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk_async", `{"name":"dup"}`, &view, "X-Request-Id", "dup")
			if rr.Code != http.StatusOK {
				ids <- fmt.Sprintf("status %d", rr.Code)
				return
			}
			ids <- view.ID
		}()
	}
	wg.Wait()
	close(ids)
	var id string
	for got := range ids {
		if id == "" {
			id = got
		}
		if got != id {
			t.Fatalf("duplicates answered %q and %q", id, got)
		}
	}
	close(env.runtime.blockSnapshot)
	waitFor(t, "the snapshot to complete", func() bool {
		var view snapshotStatusView
		rr := env.do(t, http.MethodGet, "/disk_snapshots/"+id+"/status", nil, &view)
		return rr.Code == http.StatusOK && view.Status == "complete"
	})
	if got := env.snapshotCommits(); got != 1 {
		t.Fatalf("duplicates committed %d times; want 1", got)
	}
}

// Ids that look like this facade's but do not parse are unknown snapshots.
// They must never fall through to a lookup by raw name.
func TestMalformedSnapshotIDsAreNotFound(t *testing.T) {
	env := newTestEnv(t)
	node, _ := models.EncodeNodeAffinity("worker-1")
	for _, id := range []string{"snp-", "snx-", "snp-!!.abc", "snx-!!!", "snx-" + node + ".", "snp-00ff"} {
		expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/"+id+"/status", nil, nil), http.StatusNotFound)
		expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+id, `{"name":"x"}`, nil), http.StatusNotFound)
		expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+id+"/delete", nil, nil), http.StatusOK)
		expectStatus(t, env.do(t, http.MethodPost, "/create_and_await_running", fmt.Sprintf(`{"snapshot_id":%q}`, id), nil), http.StatusBadRequest)
	}
}

// A failed metadata write leaves the devbox's metadata as it was.
func TestDevboxMetadataWriteFailureChangesNothing(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, `{"metadata":{"team":"a"}}`)
	failWrites(t, env.store, "fault_tags", "UPDATE OF tags_json ON sandboxes")
	expectError(t, env.do(t, http.MethodPost, "/"+devbox.ID, `{"metadata":{"team":"b"}}`, nil))
	var view devboxView
	expectStatus(t, env.do(t, http.MethodGet, "/"+devbox.ID, nil, &view), http.StatusOK)
	if view.Metadata["team"] != "a" {
		t.Fatalf("metadata after a failed write = %+v", view.Metadata)
	}
}

// splitSnapshotID decides which node a request is forwarded to, so it must
// hold its invariants for any input, not just the ids this facade mints.
func FuzzSplitSnapshotID(f *testing.F) {
	node, _ := models.EncodeNodeAffinity("worker-1")
	for _, seed := range []string{
		"", "plain", "snp-", "snx-", "snp-89ab", "snx-dGVhbQ",
		"snp-" + node + ".89ab", "snx-" + node + ".dGVhbQ",
		"snp-!!.x", "snx-.", "snp-..", "snp-" + node + "..x", "snx-" + node + ".",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, id string) {
		prefix, nodeID, rest, ok := splitSnapshotID(id)
		home, bound := snapshotHomeNode(id)
		_ = snapshotNameForID(id) // must not panic on anything
		if !ok {
			if prefix != "" || nodeID != "" || rest != "" || bound {
				t.Fatalf("rejected %q but returned %q %q %q (bound %v)", id, prefix, nodeID, rest, bound)
			}
			return
		}
		if prefix != snapshotPrefix && prefix != nativeSnapshotPrefix {
			t.Fatalf("%q accepted with prefix %q", id, prefix)
		}
		if rest == "" {
			t.Fatalf("%q accepted with an empty body", id)
		}
		if bound != (nodeID != "") || home != nodeID {
			t.Fatalf("%q: home %q bound %v, split node %q", id, home, bound, nodeID)
		}
		body := strings.TrimPrefix(id, prefix)
		if nodeID == "" {
			if body != rest || strings.Contains(rest, ".") {
				t.Fatalf("unbound %q split into %q", id, rest)
			}
			return
		}
		encoded, tail, _ := strings.Cut(body, ".")
		if decoded, valid := models.DecodeNodeAffinity(encoded); !valid || decoded != nodeID || tail != rest {
			t.Fatalf("bound %q split into node %q rest %q", id, nodeID, rest)
		}
	})
}

// Every native name survives the trip through a node-bound snx- id. The
// node comes back canonical: EncodeNodeAffinity trims it, as config does
// SB_NODE_ID, so " worker-1" and "worker-1" are one node.
func FuzzNativeSnapshotIDRoundTrip(f *testing.F) {
	f.Add("worker-1", "runloop/abc:latest")
	f.Add("node-a", "registry.example.com/team/image:v1.2")
	f.Add("n", "x")
	f.Fuzz(func(t *testing.T, nodeID, name string) {
		encoded, ok := models.EncodeNodeAffinity(nodeID)
		if !ok || name == "" {
			t.Skip()
		}
		id := nativeSnapshotPrefix + encoded + "." + base64.RawURLEncoding.EncodeToString([]byte(name))
		if home, bound := snapshotHomeNode(id); !bound || home != strings.TrimSpace(nodeID) {
			t.Fatalf("%q: home %q bound %v, want %q", id, home, bound, strings.TrimSpace(nodeID))
		}
		if got := snapshotNameForID(id); got != name {
			t.Fatalf("%q names %q, want %q", id, got, name)
		}
	})
}
