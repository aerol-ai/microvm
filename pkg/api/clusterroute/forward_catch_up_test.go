package clusterroute

import (
	"context"
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// catchingUpStub is a server-role client whose placement view may still be
// replaying the log after a restart.
type catchingUpStub struct {
	stubCluster
	caughtUp   bool
	resolvedID string
}

func (c *catchingUpStub) PlacementViewCaughtUp() bool { return c.caughtUp }
func (c *catchingUpStub) OwnerOfName(string, string) (string, cluster.OwnerInfo, error) {
	return c.resolvedID, c.nameOwner, c.nameErr
}

// svcWithStore is a service whose store holds the given sandbox rows.
func svcWithStore(t *testing.T, c cluster.Client, rows ...string) *service.Service {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	for _, id := range rows {
		if err := st.Create(context.Background(), &models.Sandbox{
			ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted,
			CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	svc := service.New(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	return svc
}

func rejects() int64 {
	v, err := strconv.ParseInt(expvar.Get("aerolvm_cluster_not_caught_up_rejects_total").String(), 10, 64)
	if err != nil {
		return -1
	}
	return v
}

// Every facade (v1, Daytona, E2B, Runloop) routes per-sandbox requests through
// Wrap, so this is where a view still catching up must stop answering "no
// such sandbox" and say "retry" instead — but only for ids this node does not
// hold: a local row is served.
func TestWrapWhileCatchingUp(t *testing.T) {
	peer := cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a"}
	tests := []struct {
		name       string
		stub       *catchingUpStub
		localRows  []string
		id         string
		wantStatus int // 0 = served locally
		wantFwd    bool
	}{
		{name: "unknown placement, no local row", stub: &catchingUpStub{stubCluster: stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox}}, id: "sb", wantStatus: http.StatusServiceUnavailable},
		{name: "unknown placement, local row", stub: &catchingUpStub{stubCluster: stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox}}, localRows: []string{"sb"}, id: "sb"},
		{name: "self-owned, no local row", stub: &catchingUpStub{stubCluster: stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: cluster.OwnerInfo{IsSelf: true}}}, id: "sb", wantStatus: http.StatusServiceUnavailable},
		{name: "self-owned, local row", stub: &catchingUpStub{stubCluster: stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: cluster.OwnerInfo{IsSelf: true}}}, localRows: []string{"sb"}, id: "sb"},
		{name: "owned by a peer: the peer answers", stub: &catchingUpStub{stubCluster: stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: peer}}, id: "sb", wantStatus: http.StatusAccepted, wantFwd: true},
		{name: "caught up, unknown: local handler decides", stub: &catchingUpStub{caughtUp: true, stubCluster: stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox}}, id: "sb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lh, ran := local()
			h := Wrap(svcWithStore(t, tc.stub, tc.localRows...), Options{WriteError: writeErr}, lh)
			before := rejects()
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req(tc.id))
			if tc.wantStatus == 0 {
				if !*ran {
					t.Fatalf("expected local handler to run; status %d body %q", rr.Code, rr.Body.String())
				}
				return
			}
			if *ran {
				t.Fatalf("local handler ran; wanted status %d", tc.wantStatus)
			}
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.stub.forwarded != tc.wantFwd {
				t.Fatalf("forwarded = %v, want %v", tc.stub.forwarded, tc.wantFwd)
			}
			if tc.wantStatus == http.StatusServiceUnavailable {
				if got := rr.Header().Get("Retry-After"); got != strconv.Itoa(cluster.CatchUpRetryAfterSeconds) {
					t.Fatalf("Retry-After = %q, want %d", got, cluster.CatchUpRetryAfterSeconds)
				}
				if rejects() != before+1 {
					t.Fatal("a catch-up 503 must be counted")
				}
			}
		})
	}
}

// Daytona's idOrName routes resolve a name to an id; the local-row check must
// use that id, not the name the request carried.
func TestWrapWhileCatchingUpChecksResolvedNameID(t *testing.T) {
	stub := &catchingUpStub{
		stubCluster: stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox, nameOwner: cluster.OwnerInfo{IsSelf: true}},
		resolvedID:  "sb-resolved",
	}
	for _, tc := range []struct {
		rows    []string
		wantRun bool
	}{{rows: nil, wantRun: false}, {rows: []string{"sb-resolved"}, wantRun: true}} {
		lh, ran := local()
		h := Wrap(svcWithStore(t, stub, tc.rows...), Options{PathKey: "idOrName", ResolveName: true, WriteError: writeErr}, lh)
		r := httptest.NewRequest(http.MethodGet, "/x/my-name", nil)
		r.SetPathValue("idOrName", "my-name")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if *ran != tc.wantRun {
			t.Fatalf("rows %v: local ran = %v, want %v (status %d)", tc.rows, *ran, tc.wantRun, rr.Code)
		}
		if !tc.wantRun && rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("rows %v: status = %d, want 503", tc.rows, rr.Code)
		}
	}
}

type catchingUpSnapStub struct {
	snapStub
	caughtUp bool
}

func (c *catchingUpSnapStub) PlacementViewCaughtUp() bool { return c.caughtUp }

// The snapshot home index lives in the same FSM: a snapshot registered after
// the restored Raft snapshot has no entry yet, and serving locally would 404 a
// snapshot that lives on another node.
func TestWrapSnapshotWhileCatchingUp(t *testing.T) {
	name := func(r *http.Request) string { return r.PathValue("id") }
	for _, tc := range []struct {
		name       string
		stub       *catchingUpSnapStub
		wantStatus int // 0 = served locally
	}{
		{name: "no entry while catching up", stub: &catchingUpSnapStub{snapStub: snapStub{Noop: cluster.NewNoop("self", "", "")}}, wantStatus: http.StatusServiceUnavailable},
		{name: "held here while catching up", stub: &catchingUpSnapStub{snapStub: snapStub{Noop: cluster.NewNoop("self", "", ""), home: "self", found: true}}},
		{name: "no entry once caught up", stub: &catchingUpSnapStub{caughtUp: true, snapStub: snapStub{Noop: cluster.NewNoop("self", "", "")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, ran := local()
			rr := httptest.NewRecorder()
			WrapSnapshot(svcWith(t, tc.stub), name, writeErr, h).ServeHTTP(rr, snapReq(false))
			if tc.wantStatus == 0 {
				if !*ran {
					t.Fatalf("expected local serve; status %d", rr.Code)
				}
				return
			}
			if *ran || rr.Code != tc.wantStatus || rr.Header().Get("Retry-After") == "" {
				t.Fatalf("ran=%v status=%d retry-after=%q, want %d with Retry-After", *ran, rr.Code, rr.Header().Get("Retry-After"), tc.wantStatus)
			}
		})
	}
}
