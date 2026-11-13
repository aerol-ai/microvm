package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestV1WarmPools (W1): PUT/GET/list/DELETE through the real mux, an image
// with slashes needs no escaping (and works escaped), the same PUT twice is
// a no-op, and each failure has its own status.
func TestV1WarmPools(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	pool := dockerpool.New(nil)
	env.svc.RegisterWarmPool(pool, models.RuntimeDocker)
	put := func(path string, depth int) (int, models.WarmPool) {
		rr := do(t, env.mux, http.MethodPut, path, models.WarmPoolRequest{Depth: depth})
		var p models.WarmPool
		_ = json.Unmarshal(rr.Body.Bytes(), &p)
		return rr.Code, p
	}
	if code, p := put("/v1/warm-pools/ghcr.io/acme/agent:1", 2); code != http.StatusOK || p.Image != "ghcr.io/acme/agent:1" || p.Generation != 1 || p.Status != nil {
		t.Fatalf("PUT = %d %+v", code, p)
	}
	if code, p := put("/v1/warm-pools/ghcr.io%2Facme%2Fagent%3A1", 2); code != http.StatusOK || p.Generation != 1 {
		t.Fatalf("the same PUT, escaped, must be a no-op: %d %+v", code, p)
	}
	if code, p := put("/v1/warm-pools/python:3.12", 0); code != http.StatusOK || p.Depth != 0 {
		t.Fatalf("depth 0 turns an image off: %d %+v", code, p)
	}
	// The sync is not running in this test: apply what it would.
	pool.SetConfigured([]dockerpool.Configured{{Key: dockerpool.Key{Image: "ghcr.io/acme/agent:1", Runtime: models.RuntimeDocker}, Depth: 2}})

	rr := do(t, env.mux, http.MethodGet, "/v1/warm-pools/ghcr.io/acme/agent:1", nil)
	var got models.WarmPool
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if rr.Code != http.StatusOK || got.Status == nil || got.Status.Target != 2 || got.Status.Ready != 0 || len(got.Status.Servers) != 1 {
		t.Fatalf("GET = %d %s", rr.Code, rr.Body.String())
	}
	rr = do(t, env.mux, http.MethodGet, "/v1/warm-pools", nil)
	var list models.WarmPoolList
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if rr.Code != http.StatusOK || len(list.Pools) != 2 || list.Pools[0].Image != "ghcr.io/acme/agent:1" || list.Pools[1].Status == nil {
		t.Fatalf("list = %d %s", rr.Code, rr.Body.String())
	}

	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodGet, "/v1/warm-pools/node:22", nil, http.StatusNotFound},
		{http.MethodGet, "/v1/warm-pools/", nil, http.StatusBadRequest},
		{http.MethodPut, "/v1/warm-pools/", models.WarmPoolRequest{Depth: 1}, http.StatusBadRequest},
		{http.MethodPut, "/v1/warm-pools/a%20b", models.WarmPoolRequest{Depth: 1}, http.StatusBadRequest},
		{http.MethodPut, "/v1/warm-pools/python:3.12", models.WarmPoolRequest{Depth: models.MaxWarmPoolDepth + 1}, http.StatusBadRequest},
		{http.MethodPut, "/v1/warm-pools/python:3.12", "not an object", http.StatusBadRequest},
		{http.MethodDelete, "/v1/warm-pools/", nil, http.StatusBadRequest},
		{http.MethodDelete, "/v1/warm-pools/python:3.12", nil, http.StatusNoContent},
		{http.MethodDelete, "/v1/warm-pools/python:3.12", nil, http.StatusNoContent},
	} {
		if rr := do(t, env.mux, tc.method, tc.path, tc.body); rr.Code != tc.want {
			t.Fatalf("%s %s = %d %s, want %d", tc.method, tc.path, rr.Code, rr.Body.String(), tc.want)
		}
	}

	// Past the limit a new entry is a 409; an update of an existing one is not.
	rr = do(t, env.mux, http.MethodGet, "/v1/warm-pools", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	for i := len(list.Pools); i < models.MaxWarmPools; i++ {
		if code, _ := put(fmt.Sprintf("/v1/warm-pools/img-%02d:1", i), 1); code != http.StatusOK {
			t.Fatalf("filling to the limit: %d", code)
		}
	}
	if code, _ := put("/v1/warm-pools/one-too-many:1", 1); code != http.StatusConflict {
		t.Fatalf("past the limit = %d, want 409", code)
	}
	if code, _ := put("/v1/warm-pools/ghcr.io/acme/agent:1", 3); code != http.StatusOK {
		t.Fatalf("an update at the limit = %d", code)
	}
}

// TestV1WarmPoolDemandRange (W2): a PUT with min_depth/max_depth answers
// them, and the combinations that make no sense are 400s.
func TestV1WarmPoolDemandRange(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	rr := do(t, env.mux, http.MethodPut, "/v1/warm-pools/python:3.12", map[string]int{"min_depth": 0, "max_depth": 4})
	var p models.WarmPool
	_ = json.Unmarshal(rr.Body.Bytes(), &p)
	if rr.Code != http.StatusOK || p.MaxDepth != 4 || p.MinDepth != 0 || p.Depth != 0 {
		t.Fatalf("PUT = %d %s", rr.Code, rr.Body.String())
	}
	for _, body := range []map[string]int{
		{"depth": 2, "max_depth": 4},
		{"min_depth": 1},
		{"min_depth": 5, "max_depth": 4},
		{"max_depth": models.MaxWarmPoolDepth + 1},
	} {
		if rr := do(t, env.mux, http.MethodPut, "/v1/warm-pools/python:3.12", body); rr.Code != http.StatusBadRequest {
			t.Fatalf("PUT %v = %d %s, want 400", body, rr.Code, rr.Body.String())
		}
	}
}

// TestV1WarmPoolOnImageChange (W3): the strategy defaults to replace_now
// in the answer, replace_as_used is kept, and anything else is a 400.
func TestV1WarmPoolOnImageChange(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	for _, tc := range []struct {
		body any
		want string
		code int
	}{
		{map[string]any{"depth": 1}, models.WarmPoolReplaceNow, http.StatusOK},
		{map[string]any{"depth": 1, "on_image_change": "replace_as_used"}, models.WarmPoolReplaceAsUsed, http.StatusOK},
		{map[string]any{"depth": 1, "on_image_change": "recreate"}, "", http.StatusBadRequest},
	} {
		rr := do(t, env.mux, http.MethodPut, "/v1/warm-pools/python:3.12", tc.body)
		var p models.WarmPool
		_ = json.Unmarshal(rr.Body.Bytes(), &p)
		if rr.Code != tc.code || (tc.code == http.StatusOK && p.OnImageChange != tc.want) {
			t.Fatalf("PUT %v = %d %s", tc.body, rr.Code, rr.Body.String())
		}
	}
}

// warmPoolStubCluster stands in for a server's replicated entry store.
type warmPoolStubCluster struct {
	*cluster.Noop
	writeErr error
	readErr  error
	wrote    cluster.WarmPoolWriteRequest
}

func (s *warmPoolStubCluster) WriteWarmPool(_ context.Context, req cluster.WarmPoolWriteRequest) (cluster.WarmPoolWriteResponse, error) {
	s.wrote = req
	if s.writeErr != nil {
		return cluster.WarmPoolWriteResponse{}, s.writeErr
	}
	p := req.Pool
	p.Generation = 4
	return cluster.WarmPoolWriteResponse{Pool: p, Changed: true}, nil
}

func (s *warmPoolStubCluster) ReadWarmPools(_ context.Context, req cluster.WarmPoolReadRequest) (cluster.WarmPoolReadResponse, error) {
	if s.readErr != nil {
		return cluster.WarmPoolReadResponse{}, s.readErr
	}
	return cluster.WarmPoolReadResponse{Version: 9, Pools: []cluster.WarmPoolRecord{{Image: "python:3.12", Depth: 2}}, Authoritative: true}, nil
}

func TestClusterInternalWarmPoolRoutes(t *testing.T) {
	stub := &warmPoolStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)
	call := func(fn http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		fn(rr, withPeer(httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)), "wrk-a"))
		return rr
	}
	write := `{"pool":{"image":"python:3.12","depth":2}}`
	rr := call(h.clusterInternalWarmPoolWrite, cluster.PublicInternalWarmPoolWritePath, write)
	var out cluster.WarmPoolWriteResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.Pool.Generation != 4 || stub.wrote.Pool.Image != "python:3.12" {
		t.Fatalf("write = %d %+v", rr.Code, out)
	}
	// FSM refusals answer 200 with a code; anything else is a retryable 503.
	for _, refusal := range []error{cluster.ErrWarmPoolLimit, cluster.ErrClusterVersion} {
		stub.writeErr = refusal
		rr = call(h.clusterInternalWarmPoolWrite, cluster.PublicInternalWarmPoolWritePath, write)
		out = cluster.WarmPoolWriteResponse{}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		if rr.Code != http.StatusOK || out.Code == "" {
			t.Fatalf("refusal %v = %d %+v", refusal, rr.Code, out)
		}
	}
	stub.writeErr = errors.New("raft apply timed out")
	if rr := call(h.clusterInternalWarmPoolWrite, cluster.PublicInternalWarmPoolWritePath, write); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("transient = %d", rr.Code)
	}
	if rr := call(h.clusterInternalWarmPoolWrite, cluster.PublicInternalWarmPoolWritePath, "not json"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d", rr.Code)
	}

	rr = call(h.clusterInternalWarmPoolRead, cluster.PublicInternalWarmPoolReadPath, `{"since":3}`)
	var read cluster.WarmPoolReadResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &read)
	if rr.Code != http.StatusOK || len(read.Pools) != 1 || !read.Authoritative || read.Version != 9 {
		t.Fatalf("read = %d %+v", rr.Code, read)
	}
	stub.readErr = errors.New("no fsm")
	if rr := call(h.clusterInternalWarmPoolRead, cluster.PublicInternalWarmPoolReadPath, `{}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("read error = %d", rr.Code)
	}
	if rr := call(h.clusterInternalWarmPoolRead, cluster.PublicInternalWarmPoolReadPath, "x"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad read body = %d", rr.Code)
	}

	// A node without a replicated store says so.
	stateless := newOwnedRecoveryHandlers(t, cluster.NewNoop("srv", "http://srv", ""))
	if rr := call(stateless.clusterInternalWarmPoolWrite, cluster.PublicInternalWarmPoolWritePath, write); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stateless write = %d", rr.Code)
	}
	if rr := call(stateless.clusterInternalWarmPoolRead, cluster.PublicInternalWarmPoolReadPath, `{}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stateless read = %d", rr.Code)
	}
}

// TestV1WarmPoolsClusterUnavailable: in a cluster, an unreachable store is
// a retryable 503 whose message does not leak the cause.
func TestV1WarmPoolsClusterUnavailable(t *testing.T) {
	env := newCustomDomainsV1Env(t, func(cfg *config.Config) { cfg.EnableCluster = true })
	stub := &warmPoolStubCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), readErr: errors.New("dial 10.0.0.9:7443: refused")}
	env.svc.AttachCluster(stub)
	rr := do(t, env.mux, http.MethodGet, "/v1/warm-pools", nil)
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" || strings.Contains(rr.Body.String(), "10.0.0.9") {
		t.Fatalf("list = %d %s", rr.Code, rr.Body.String())
	}
	stub.writeErr = cluster.ErrWarmPoolLimit
	if rr := do(t, env.mux, http.MethodPut, "/v1/warm-pools/python:3.12", models.WarmPoolRequest{Depth: 1}); rr.Code != http.StatusConflict {
		t.Fatalf("limit through the cluster = %d", rr.Code)
	}
}

// TestCapacityHidesWarmPoolsFromNonAdmins: the per-entry status on
// /v1/capacity names the images an operator runs, like the warm-pool API
// it serves; only fleet admins (and peers) see it.
func TestCapacityHidesWarmPoolsFromNonAdmins(t *testing.T) {
	env := newCustomDomainsV1Env(t, nil)
	pool := dockerpool.New(nil)
	pool.SetConfigured([]dockerpool.Configured{{Key: dockerpool.Key{Image: "internal.registry/app:1"}, Depth: 1}})
	env.svc.RegisterWarmPool(pool, models.RuntimeDocker)
	h := &handlers{deps: Deps{Service: env.svc}}
	for name, tc := range map[string]struct {
		access  controlplane.Access
		redacts bool
	}{
		"fleet viewer": {fleetToken(controlplane.RoleViewer), true},
		"admin":        {fleetToken(controlplane.RoleAdmin), false},
		"operator":     {controlplane.OperatorAccess(), false},
		"peer":         {controlplane.NodeAccess("n2"), false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/capacity", nil)
		req = req.WithContext(controlplane.ContextWithAccess(req.Context(), tc.access))
		rec := httptest.NewRecorder()
		h.capacity(rec, req)
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if _, exposed := body["warm_pools"]; exposed == tc.redacts {
			t.Errorf("%s: warm_pools exposed=%v, want %v", name, exposed, !tc.redacts)
		}
	}
}

// runStateStubCluster records the batch an owner sends.
type runStateStubCluster struct {
	*cluster.Noop
	got []cluster.RunStateReport
	err error
}

func (s *runStateStubCluster) SetRunStates(_ context.Context, reports []cluster.RunStateReport) (int, error) {
	s.got = reports
	return len(reports), s.err
}

func TestClusterInternalRunStates(t *testing.T) {
	stub := &runStateStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)
	call := func(h *handlers, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.clusterInternalRunStates(rr, withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalRunStatesPath, strings.NewReader(body)), "wrk-a"))
		return rr
	}
	batch := `{"reports":[{"sandbox_id":"sb-a","incarnation_id":"inc-a","owner_node_id":"wrk-a","state":"suspended"}]}`
	rr := call(h, batch)
	var out cluster.RunStateWriteResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.Applied != 1 || len(stub.got) != 1 || stub.got[0].State != cluster.RunStateSuspended {
		t.Fatalf("batch = %d %+v %+v", rr.Code, out, stub.got)
	}
	for _, tc := range []struct {
		name string
		err  error
		body string
		want int
	}{
		{"bad JSON", nil, "x", http.StatusBadRequest},
		{"bad batch", cluster.ErrBadRunStateBatch, batch, http.StatusBadRequest},
		{"transient", errors.New("raft apply timed out"), batch, http.StatusServiceUnavailable},
	} {
		stub.err = tc.err
		if rr := call(h, tc.body); rr.Code != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, rr.Code, tc.want)
		}
	}
	stateless := newOwnedRecoveryHandlers(t, cluster.NewNoop("srv", "http://srv", ""))
	if rr := call(stateless, batch); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stateless = %d", rr.Code)
	}
}

type specSummaryStubCluster struct {
	*cluster.Noop
	err error
}

func (s *specSummaryStubCluster) SpecSummaries(_ context.Context, ids []string) (map[string]cluster.SpecSummary, error) {
	if s.err != nil {
		return nil, s.err
	}
	return map[string]cluster.SpecSummary{ids[0]: {Image: "python:3.12", Version: 4}}, nil
}

func TestClusterInternalSpecSummaries(t *testing.T) {
	stub := &specSummaryStubCluster{Noop: cluster.NewNoop("srv", "http://srv", "")}
	h := newOwnedRecoveryHandlers(t, stub)
	call := func(h *handlers, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.clusterInternalSpecSummaries(rr, withPeer(httptest.NewRequest(http.MethodPost, cluster.PublicInternalSpecSummariesPath, strings.NewReader(body)), "gw-a"))
		return rr
	}
	rr := call(h, `{"ids":["sb-a"]}`)
	var out cluster.SpecSummariesResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.Summaries["sb-a"].Image != "python:3.12" {
		t.Fatalf("summaries = %d %+v", rr.Code, out)
	}
	for _, tc := range []struct {
		name string
		err  error
		body string
		want int
	}{
		{"bad JSON", nil, "x", http.StatusBadRequest},
		{"bad batch", cluster.ErrBadSpecSummaryBatch, `{"ids":[]}`, http.StatusBadRequest},
		{"transient", errors.New("no fsm"), `{"ids":["sb-a"]}`, http.StatusServiceUnavailable},
	} {
		stub.err = tc.err
		if rr := call(h, tc.body); rr.Code != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, rr.Code, tc.want)
		}
	}
	stateless := newOwnedRecoveryHandlers(t, cluster.NewNoop("srv", "http://srv", ""))
	if rr := call(stateless, `{"ids":["sb-a"]}`); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stateless = %d", rr.Code)
	}
}
