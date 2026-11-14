package clusterroute

import (
	"bytes"
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

var federationKey = bytes.Repeat([]byte{7}, 32)

// mintIn mints a sandbox id the way a node of the given cell does.
func mintIn(t *testing.T, cell int) string {
	t.Helper()
	minter := service.New(config.Config{CellID: cell, CellIDKey: federationKey}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
	id, err := minter.NewSandboxID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// cellSvc is a cell-1 service of a federation whose cell 2 is at
// https://cell2.example.com.
func cellSvc(t *testing.T, c cluster.Client, localRows ...string) *service.Service {
	t.Helper()
	cfg := config.Config{CellID: 1, CellIDKey: federationKey, CellEndpoints: map[int]string{2: "https://cell2.example.com"}}
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	for _, id := range localRows {
		if err := st.Create(context.Background(), &models.Sandbox{
			ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted,
			CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	svc := service.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	return svc
}

func cellRedirects() int64 {
	v, _ := strconv.ParseInt(expvar.Get("aerolvm_cell_redirects_total").String(), 10, 64)
	return v
}

// C16: a request for a sandbox minted in another cell is answered 421 with
// that cell's address, and only when this cell does not know the sandbox.
func TestWrapRedirectsToTheSandboxCell(t *testing.T) {
	peer := cluster.OwnerInfo{NodeID: "worker-a", APIURL: "http://worker-a"}
	unknown := func() cluster.Client {
		return &stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox}
	}
	for _, tc := range []struct {
		name       string
		cluster    func() cluster.Client
		cell       int
		heldHere   bool
		forwarded  bool
		wantStatus int // 0 = served locally
		wantFwd    bool
	}{
		{name: "single node: another cell's sandbox", cluster: func() cluster.Client { return cluster.NewNoop("self", "", "") }, cell: 2, wantStatus: http.StatusMisdirectedRequest},
		{name: "single node: this cell's sandbox", cluster: func() cluster.Client { return cluster.NewNoop("self", "", "") }, cell: 1},
		{name: "single node: a cell with no address", cluster: func() cluster.Client { return cluster.NewNoop("self", "", "") }, cell: 3},
		{name: "single node: held here", cluster: func() cluster.Client { return cluster.NewNoop("self", "", "") }, cell: 2, heldHere: true},
		{name: "cluster: unknown here, another cell's", cluster: unknown, cell: 2, wantStatus: http.StatusMisdirectedRequest},
		{name: "cluster: unknown here, this cell's", cluster: unknown, cell: 1},
		{name: "cluster: a forward is never redirected", cluster: unknown, cell: 2, forwarded: true},
		{
			name: "cluster: catching up answers 503, not a guess",
			cluster: func() cluster.Client {
				return &catchingUpStub{stubCluster: stubCluster{Noop: cluster.NewNoop("self", "", ""), ownerErr: cluster.ErrUnknownSandbox}}
			},
			cell: 2, wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:    "cluster: a placement here wins over the id",
			cluster: func() cluster.Client { return &stubCluster{Noop: cluster.NewNoop("self", "", ""), owner: peer} },
			cell:    2, wantStatus: http.StatusAccepted, wantFwd: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.cluster()
			id := mintIn(t, tc.cell)
			var rows []string
			if tc.heldHere {
				rows = []string{id}
			}
			svc := cellSvc(t, c, rows...)
			lh, ran := local()
			r := req(id)
			if tc.forwarded {
				r.Header.Set(cluster.HeaderForwarded, "1")
			}
			before := cellRedirects()
			rr := httptest.NewRecorder()
			Wrap(svc, Options{WriteError: writeErr}, lh).ServeHTTP(rr, r)

			if tc.wantStatus == 0 {
				if !*ran {
					t.Fatalf("status %d, want served locally", rr.Code)
				}
			} else if *ran || rr.Code != tc.wantStatus {
				t.Fatalf("ran=%v status=%d, want %d", *ran, rr.Code, tc.wantStatus)
			}
			if stub, ok := c.(*stubCluster); ok && stub.forwarded != tc.wantFwd {
				t.Fatalf("forwarded=%v, want %v", stub.forwarded, tc.wantFwd)
			}
			redirected := tc.wantStatus == http.StatusMisdirectedRequest
			if got := rr.Header().Get(models.CellEndpointHeader); (got == "https://cell2.example.com") != redirected || (!redirected && got != "") {
				t.Fatalf("%s = %q, redirected=%v", models.CellEndpointHeader, got, redirected)
			}
			if got := cellRedirects() - before; got != map[bool]int64{true: 1, false: 0}[redirected] {
				t.Fatalf("aerolvm_cell_redirects_total rose by %d", got)
			}
		})
	}
}
