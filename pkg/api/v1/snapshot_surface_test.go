package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

func seedSnap(t *testing.T, st interface {
	CreateSnapshot(context.Context, *models.SandboxSnapshot) error
}, name string, at time.Time) {
	t.Helper()
	if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
		Name: name, Image: "img-" + name, CreatedAt: at,
	}); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

func TestV1ListSnapshots(t *testing.T) {
	h, st := newClusterCreateHarness(t, &apiRecordingRuntime{}, cluster.NewNoop("self", "", ""))
	now := time.Now().UTC()
	seedSnap(t, st, "snap-a", now)
	seedSnap(t, st, "snap-b", now)
	seedSnap(t, st, "snap-c", now)

	// Full list.
	rr := httptest.NewRecorder()
	h.listSnapshots(rr, httptest.NewRequest(http.MethodGet, "/v1/snapshots", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp snapshotListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Snapshots) != 3 || resp.HasMore {
		t.Fatalf("list = %d snapshots, has_more=%v; want 3/false", len(resp.Snapshots), resp.HasMore)
	}

	// Paged: limit=2 → has_more; cursor skips.
	rr = httptest.NewRecorder()
	h.listSnapshots(rr, httptest.NewRequest(http.MethodGet, "/v1/snapshots?limit=2", nil))
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Snapshots) != 2 || !resp.HasMore {
		t.Fatalf("limit=2 → %d/has_more=%v, want 2/true", len(resp.Snapshots), resp.HasMore)
	}
	rr = httptest.NewRecorder()
	h.listSnapshots(rr, httptest.NewRequest(http.MethodGet, "/v1/snapshots?starting_after=snap-b", nil))
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Snapshots) != 1 || resp.Snapshots[0].Name != "snap-c" {
		t.Fatalf("starting_after=snap-b → %+v, want [snap-c]", resp.Snapshots)
	}

	// Bad limit → 400.
	rr = httptest.NewRecorder()
	h.listSnapshots(rr, httptest.NewRequest(http.MethodGet, "/v1/snapshots?limit=abc", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad limit status = %d, want 400", rr.Code)
	}
}

func TestV1GetAndDeleteSnapshot(t *testing.T) {
	h, st := newClusterCreateHarness(t, &apiRecordingRuntime{}, cluster.NewNoop("self", "", ""))
	seedSnap(t, st, "snap-x", time.Now().UTC())

	get := func(name string) int {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/snapshots/"+name, nil)
		req.SetPathValue("id", name)
		h.getSnapshot(rr, req)
		return rr.Code
	}
	if code := get("snap-x"); code != http.StatusOK {
		t.Fatalf("get existing = %d, want 200", code)
	}
	if code := get("missing"); code != http.StatusNotFound {
		t.Fatalf("get missing = %d, want 404", code)
	}

	del := func(name string) int {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/v1/snapshots/"+name, nil)
		req.SetPathValue("id", name)
		h.deleteSnapshot(rr, req)
		return rr.Code
	}
	if code := del("snap-x"); code != http.StatusNoContent {
		t.Fatalf("delete existing = %d, want 204", code)
	}
	if code := get("snap-x"); code != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404", code)
	}
	if code := del("snap-x"); code != http.StatusNotFound {
		t.Fatalf("delete missing = %d, want 404", code)
	}
}

// A store error on the list path surfaces as a store-aware error, not a panic.
func TestV1ListSnapshotsStoreError(t *testing.T) {
	h, st := newClusterCreateHarness(t, &apiRecordingRuntime{}, cluster.NewNoop("self", "", ""))
	_ = st.Close() // the harness cleanup tolerates the double close
	rr := httptest.NewRecorder()
	h.listSnapshots(rr, httptest.NewRequest(http.MethodGet, "/v1/snapshots", nil))
	// The store error must surface as an HTTP error (via WriteStoreAwareError),
	// not a 200 or a panic — the exact status is the mapper's call.
	if rr.Code < http.StatusBadRequest {
		t.Fatalf("list on a closed store = %d, want an error status", rr.Code)
	}
}

type v1SnapRouteStub struct {
	*cluster.Noop
	home      string
	members   []cluster.Member
	forwarded bool
}

func (c *v1SnapRouteStub) SnapshotHomeNode(context.Context, string) (string, bool, error) {
	return c.home, c.home != "", nil
}
func (c *v1SnapRouteStub) Members() []cluster.Member { return c.members }
func (c *v1SnapRouteStub) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, _ *http.Request) {
	c.forwarded = true
	w.WriteHeader(http.StatusAccepted)
}

// A v1 snapshot-by-id GET/DELETE whose home is another node forwards there.
func TestV1SnapshotByIDForwardsToHomeNode(t *testing.T) {
	h, _ := newClusterCreateHarness(t, &apiRecordingRuntime{}, cluster.NewNoop("self", "", ""))
	stub := &v1SnapRouteStub{
		Noop:    cluster.NewNoop("self", "", ""),
		home:    "worker-a",
		members: []cluster.Member{{NodeID: "worker-a", APIURL: "http://worker-a", Alive: true}},
	}
	h.deps.Service.AttachCluster(stub)

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		stub.forwarded = false
		req := httptest.NewRequest(method, "/v1/snapshots/snap-a", nil)
		req.SetPathValue("id", "snap-a")
		rr := httptest.NewRecorder()
		h.snapshotForwardWrap(http.HandlerFunc(h.getSnapshot)).ServeHTTP(rr, req)
		if !stub.forwarded || rr.Code != http.StatusAccepted {
			t.Fatalf("%s: forwarded=%v code=%d, want forwarded/202", method, stub.forwarded, rr.Code)
		}
	}
}
