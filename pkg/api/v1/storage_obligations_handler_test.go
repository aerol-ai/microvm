package v1

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
)

type obligationViewCluster struct {
	*retirementMembersCluster
	views []cluster.StorageObligationView
	err   error
}

func (c *obligationViewCluster) StorageObligations(context.Context) ([]cluster.StorageObligationView, error) {
	return c.views, c.err
}

func newObligationHandlers(t *testing.T, c cluster.Client) *handlers {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := service.New(config.Config{DBPath: dbPath, EnableCluster: true}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	t.Cleanup(svc.CloseSecretAuditSink)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}
}

func viewCluster(views []cluster.StorageObligationView, err error) *obligationViewCluster {
	return &obligationViewCluster{
		retirementMembersCluster: &retirementMembersCluster{Noop: cluster.NewNoop("node-self", "http://node-self", "")},
		views:                    views, err: err,
	}
}

// UC-160: the list carries the open decommission jobs next to the
// attestations, from the local view — and a failed read fails the request
// instead of showing an empty (all-clear) list.
func TestStorageRetirementsListIncludesObligations(t *testing.T) {
	h := newObligationHandlers(t, viewCluster([]cluster.StorageObligationView{
		{NodeID: "worker-x", Holders: 1, PendingDeletes: 2, Complete: false,
			StaleReporters: []cluster.StorageObligationReporter{{NodeID: "owner-c", Stale: true}}},
	}, nil))
	rr := httptest.NewRecorder()
	h.clusterListNodeStorageRetirements(rr, asOperator(httptest.NewRequest(http.MethodGet, "/v1/cluster/storage-retirements", nil), true))
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Retirements []any                           `json:"retirements"`
		Obligations []cluster.StorageObligationView `json:"obligations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Obligations) != 1 || got.Obligations[0].NodeID != "worker-x" || got.Obligations[0].Complete ||
		len(got.Obligations[0].StaleReporters) != 1 {
		t.Fatalf("obligations = %+v", got.Obligations)
	}

	empty := newObligationHandlers(t, viewCluster(nil, nil))
	er := httptest.NewRecorder()
	empty.clusterListNodeStorageRetirements(er, asOperator(httptest.NewRequest(http.MethodGet, "/v1/cluster/storage-retirements", nil), true))
	if er.Code != http.StatusOK || !json.Valid(er.Body.Bytes()) || !containsJSONKey(er.Body.Bytes(), "obligations") {
		t.Fatalf("no jobs must still render an obligations array: %d %s", er.Code, er.Body.String())
	}

	failing := newObligationHandlers(t, viewCluster(nil, errors.New("control plane unreachable")))
	fr := httptest.NewRecorder()
	failing.clusterListNodeStorageRetirements(fr, asOperator(httptest.NewRequest(http.MethodGet, "/v1/cluster/storage-retirements", nil), true))
	if fr.Code == http.StatusOK {
		t.Fatal("an unreadable obligation view rendered 200 — that reads as nothing owed")
	}
}

func TestClusterInternalStorageObligations(t *testing.T) {
	h := newObligationHandlers(t, viewCluster([]cluster.StorageObligationView{{NodeID: "worker-x"}}, nil))
	rr := httptest.NewRecorder()
	h.clusterInternalStorageObligations(rr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalStorageObligationsPath, nil))
	var resp cluster.StorageObligationsResponse
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &resp) != nil || len(resp.Obligations) != 1 {
		t.Fatalf("internal view = %d %s", rr.Code, rr.Body.String())
	}
	nilView := newObligationHandlers(t, viewCluster(nil, nil))
	nr := httptest.NewRecorder()
	nilView.clusterInternalStorageObligations(nr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalStorageObligationsPath, nil))
	if nr.Code != http.StatusOK || !containsJSONKey(nr.Body.Bytes(), "obligations") {
		t.Fatalf("empty internal view = %d %s", nr.Code, nr.Body.String())
	}
	failing := newObligationHandlers(t, viewCluster(nil, errors.New("boom")))
	fr := httptest.NewRecorder()
	failing.clusterInternalStorageObligations(fr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalStorageObligationsPath, nil))
	if fr.Code == http.StatusOK {
		t.Fatal("a failed internal read answered 200")
	}
	noReader := newObligationHandlers(t, cluster.NewNoop("n", "", ""))
	xr := httptest.NewRecorder()
	noReader.clusterInternalStorageObligations(xr, httptest.NewRequest(http.MethodGet, cluster.PublicInternalStorageObligationsPath, nil))
	if xr.Code != http.StatusServiceUnavailable {
		t.Fatalf("a node with no view = %d, want 503", xr.Code)
	}
}

func containsJSONKey(body []byte, key string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
