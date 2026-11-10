package v1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Tests for the cluster upgrade routes (cluster_upgrade.go) against stub
// cluster clients: answers, error mapping, leader forwarding, the
// soft-frozen-safe 409 under Noop, and the peer routes.

// upgradeStub is a server that leads (or not) with canned rollout answers.
type upgradeStub struct {
	*cluster.Noop
	leader     string
	rollout    *upgradewire.Rollout
	created    bool
	err        error
	applyReq   upgradewire.ApplyRequest
	caller     string
	command    string
	transferTo string
	stepReq    cluster.UpgradeStepRequest
	stepCaller string
	stepResp   cluster.UpgradeStepResponse
	stepErr    error
	fence      cluster.UpgradeFence
	fenceErr   error
	has        bool
	putCreated bool
	putErr     error
	putBody    string
	served     string
	forwarded  int
}

func newUpgradeStub() *upgradeStub {
	return &upgradeStub{Noop: cluster.NewNoop("srv-1", "http://srv-1", ""), leader: "srv-1", rollout: &upgradewire.Rollout{ID: "r1", State: upgradewire.StateStaging}}
}

func (s *upgradeStub) Leader() string { return s.leader }
func (s *upgradeStub) GetRollout(context.Context) (*upgradewire.Rollout, error) {
	return s.rollout, s.err
}
func (s *upgradeStub) ApplyRollout(_ context.Context, caller string, req upgradewire.ApplyRequest) (*upgradewire.Rollout, bool, error) {
	s.caller, s.applyReq = caller, req
	if s.err != nil {
		return nil, false, s.err
	}
	return s.rollout, s.created, nil
}
func (s *upgradeStub) RolloutCommand(_ context.Context, caller, command string) (*upgradewire.Rollout, error) {
	s.caller, s.command = caller, command
	if s.err != nil {
		return nil, s.err
	}
	return s.rollout, nil
}
func (s *upgradeStub) TransferLeadership(_ context.Context, to string) (upgradewire.LeaderTransferResponse, error) {
	s.transferTo = to
	return upgradewire.LeaderTransferResponse{Leader: "srv-2", Term: 4}, s.err
}
func (s *upgradeStub) UpgradeStep(_ context.Context, caller string, req cluster.UpgradeStepRequest) (cluster.UpgradeStepResponse, error) {
	s.stepCaller, s.stepReq = caller, req
	return s.stepResp, s.stepErr
}
func (s *upgradeStub) UpgradeStatus(_ context.Context, op string) cluster.UpgradeNodeStatus {
	return cluster.UpgradeNodeStatus{NodeID: "srv-1", Op: op, Version: "v1"}
}
func (s *upgradeStub) UpgradeFenceFor(context.Context, string, string) (cluster.UpgradeFence, error) {
	return s.fence, s.fenceErr
}
func (s *upgradeStub) ServeUpgradeFile(w http.ResponseWriter, _ *http.Request, caller, sum string) {
	s.served = caller + " " + sum
	_, _ = w.Write([]byte("bytes"))
}
func (s *upgradeStub) PutUpgradeFile(_ context.Context, _ string, body io.Reader) (bool, int64, error) {
	b, _ := io.ReadAll(body)
	s.putBody = string(b)
	return s.putCreated, int64(len(b)), s.putErr
}
func (s *upgradeStub) HasUpgradeFile(string) (bool, error) { return s.has, nil }
func (s *upgradeStub) LookupMember(id string) (cluster.Member, bool) {
	return cluster.Member{NodeID: id, Alive: true, InternalURL: "https://" + id}, true
}
func (s *upgradeStub) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, _ *http.Request) {
	s.forwarded++
	w.WriteHeader(http.StatusTeapot)
}

func hexSum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestClusterUpgradeRoutesOnTheLeader(t *testing.T) {
	stub := newUpgradeStub()
	mux := joinRoutesMux(t, stub, joinOperator())
	if rr := serveBody(mux, http.MethodGet, "/v1/cluster/upgrade", ""); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"r1"`) {
		t.Fatalf("get = %d %s", rr.Code, rr.Body.String())
	}
	stub.created = true
	rr := serveBody(mux, http.MethodPost, "/v1/cluster/upgrade", `{"version":"v2","files":{"sandboxd":"x"},"source":"upload"}`)
	if rr.Code != http.StatusCreated || stub.applyReq.Version != "v2" || stub.caller != "operator:operator:alice" {
		t.Fatalf("apply = %d %s caller %q", rr.Code, rr.Body.String(), stub.caller)
	}
	stub.created = false
	if rr := serveBody(mux, http.MethodPost, "/v1/cluster/upgrade", `{"version":"v2"}`); rr.Code != http.StatusOK {
		t.Fatalf("repeat apply = %d", rr.Code)
	}
	if rr := serveBody(mux, http.MethodPost, "/v1/cluster/upgrade", `{`); rr.Code != http.StatusBadRequest {
		t.Fatalf("broken body = %d", rr.Code)
	}
	for path, cmd := range map[string]string{
		upgradewire.ClusterUpgradeStopPath: cluster.RolloutStop, upgradewire.ClusterUpgradeResumePath: cluster.RolloutResume,
		upgradewire.ClusterUpgradeFinalizePath: cluster.RolloutFinalize, upgradewire.ClusterUpgradeRollbackPath: cluster.RolloutRollback,
	} {
		if rr := serveBody(mux, http.MethodPost, path, ""); rr.Code != http.StatusOK || stub.command != cmd {
			t.Fatalf("%s = %d (%s)", path, rr.Code, stub.command)
		}
	}
	if rr := serveBody(mux, http.MethodPost, upgradewire.ClusterLeaderTransferPath, `{"to":"srv-2"}`); rr.Code != http.StatusOK || stub.transferTo != "srv-2" || !strings.Contains(rr.Body.String(), `"leader":"srv-2"`) {
		t.Fatalf("transfer = %d %s", rr.Code, rr.Body.String())
	}
	if rr := serveBody(mux, http.MethodPost, upgradewire.ClusterLeaderTransferPath, ""); rr.Code != http.StatusOK || stub.transferTo != "" {
		t.Fatalf("transfer with no body = %d", rr.Code)
	}
	if rr := serveBody(mux, http.MethodPost, upgradewire.ClusterLeaderTransferPath, `{`); rr.Code != http.StatusBadRequest {
		t.Fatalf("transfer broken body = %d", rr.Code)
	}
}

func TestClusterUpgradeErrorMapping(t *testing.T) {
	stub := newUpgradeStub()
	mux := joinRoutesMux(t, stub, joinOperator())
	cases := []struct {
		err  error
		code int
		body string
	}{
		{&cluster.RolloutError{Status: http.StatusConflict, Body: upgradewire.ErrorResponse{Error: upgradewire.ErrCodeSkippedNodes, Nodes: []string{"w1"}}}, http.StatusConflict, `"nodes":["w1"]`},
		{&cluster.UpgradeStepError{Status: http.StatusServiceUnavailable, Code: "retry", Reason: "busy"}, http.StatusServiceUnavailable, `"retry"`},
		{cluster.ErrNotCaughtUp, http.StatusServiceUnavailable, ""},
		{cluster.ErrNotLeader, http.StatusServiceUnavailable, "not_leader"},
		{cluster.ErrClusterVersion, http.StatusConflict, "cluster_version"},
		{context.DeadlineExceeded, http.StatusGatewayTimeout, "timeout"},
		{errors.New("boom"), http.StatusInternalServerError, "internal"},
	}
	for _, tc := range cases {
		stub.err = tc.err
		rr := serveBody(mux, http.MethodPost, upgradewire.ClusterUpgradeStopPath, "")
		if rr.Code != tc.code || !strings.Contains(rr.Body.String(), tc.body) {
			t.Fatalf("%v = %d %s", tc.err, rr.Code, rr.Body.String())
		}
	}
	stub.err = errors.New("x")
	for _, path := range []string{upgradewire.ClusterUpgradePath} {
		if rr := serveBody(mux, http.MethodGet, path, ""); rr.Code != http.StatusInternalServerError {
			t.Fatalf("get error = %d", rr.Code)
		}
		if rr := serveBody(mux, http.MethodPost, path, `{}`); rr.Code != http.StatusInternalServerError {
			t.Fatalf("apply error = %d", rr.Code)
		}
	}
	if rr := serveBody(mux, http.MethodPost, upgradewire.ClusterLeaderTransferPath, `{}`); rr.Code != http.StatusInternalServerError {
		t.Fatalf("transfer error = %d", rr.Code)
	}
}

func TestClusterUpgradeForwardsToLeader(t *testing.T) {
	stub := newUpgradeStub()
	stub.leader = "srv-2"
	mux := joinRoutesMux(t, stub, joinOperator())
	if rr := serveBody(mux, http.MethodPost, upgradewire.ClusterUpgradeStopPath, ""); rr.Code != http.StatusTeapot || stub.forwarded != 1 || stub.command != "" {
		t.Fatalf("follower stop = %d forwarded %d", rr.Code, stub.forwarded)
	}
	// A call already forwarded once never forwards again.
	req := httptest.NewRequest(http.MethodPost, upgradewire.ClusterUpgradeStopPath, nil)
	req.Header.Set(clusterUpgradeLeaderHeader, "1")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable || stub.forwarded != 1 {
		t.Fatalf("second hop = %d", rr.Code)
	}
	// A follower server reads the rollout itself.
	if rr := serveBody(mux, http.MethodGet, upgradewire.ClusterUpgradePath, ""); rr.Code != http.StatusOK {
		t.Fatalf("follower get = %d", rr.Code)
	}
}

func TestClusterUpgradeOffClusterMode(t *testing.T) {
	mux := joinRoutesMux(t, cluster.NewNoop("solo", "http://solo", ""), joinOperator())
	sum := hexSum("x")
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, upgradewire.ClusterUpgradePath}, {http.MethodPost, upgradewire.ClusterUpgradePath},
		{http.MethodPost, upgradewire.ClusterUpgradeStopPath}, {http.MethodPost, upgradewire.ClusterLeaderTransferPath},
		{http.MethodPut, upgradewire.ClusterUpgradeFilesPath + "/" + sum},
	} {
		rr := serveBody(mux, c.method, c.path, "{}")
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), upgradewire.ErrCodeNotClusterMode) {
			t.Fatalf("%s %s on a single node = %d %s", c.method, c.path, rr.Code, rr.Body.String())
		}
	}
}

func TestClusterUpgradeFileRoutes(t *testing.T) {
	stub := newUpgradeStub()
	mux := joinRoutesMux(t, stub, joinOperator())
	sum := hexSum("payload")
	if rr := serveBody(mux, http.MethodPut, upgradewire.ClusterUpgradeFilesPath+"/NOTHEX", "x"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad path = %d", rr.Code)
	}
	stub.putCreated = true
	rr := serveBody(mux, http.MethodPut, upgradewire.ClusterUpgradeFilesPath+"/"+sum, "payload")
	if rr.Code != http.StatusCreated || stub.putBody != "payload" {
		t.Fatalf("put = %d %s", rr.Code, rr.Body.String())
	}
	stub.putCreated = false
	if rr := serveBody(mux, http.MethodPut, upgradewire.ClusterUpgradeFilesPath+"/"+sum, "payload"); rr.Code != http.StatusOK {
		t.Fatalf("repeat put = %d", rr.Code)
	}
	for err, code := range map[error]int{
		nodeupgrade.ErrHashMismatch: http.StatusBadRequest, cluster.ErrUploadQuota: http.StatusInsufficientStorage,
		errors.New("larger than 256 bytes"): http.StatusRequestEntityTooLarge, errors.New("disk"): http.StatusBadRequest,
	} {
		stub.putErr = err
		if rr := serveBody(mux, http.MethodPut, upgradewire.ClusterUpgradeFilesPath+"/"+sum, "payload"); rr.Code != code {
			t.Fatalf("put %v = %d, want %d", err, rr.Code, code)
		}
	}
	big := httptest.NewRequest(http.MethodPut, upgradewire.ClusterUpgradeFilesPath+"/"+sum, strings.NewReader("x"))
	big.ContentLength = upgradewire.MaxUploadBytes + 1
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, big)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large = %d", rr.Code)
	}
	if rr := serveBody(mux, http.MethodHead, upgradewire.ClusterUpgradeFilesPath+"/"+sum, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("head missing = %d", rr.Code)
	}
	stub.has = true
	if rr := serveBody(mux, http.MethodHead, upgradewire.ClusterUpgradeFilesPath+"/"+sum, ""); rr.Code != http.StatusOK {
		t.Fatalf("head present = %d", rr.Code)
	}
}

func TestClusterNodeUpgradePeerRoutes(t *testing.T) {
	stub := newUpgradeStub()
	h := joinHandlers(t, stub)
	call := func(fn http.HandlerFunc, method, path, body, peer, id string) *httptest.ResponseRecorder {
		req := internalReq(method, path, body, peer)
		req.SetPathValue("id", id)
		req.SetPathValue("sha256", strings.TrimPrefix(path, cluster.PublicInternalUpgradeFilesPath))
		rr := httptest.NewRecorder()
		fn(rr, req)
		return rr
	}
	stub.stepResp = cluster.UpgradeStepResponse{State: cluster.UpgradeNodeStarted, Op: "op1"}
	rr := call(h.clusterNodeUpgradeStep, http.MethodPost, "/v1/cluster/nodes/srv-1/upgrade", `{"rollout_id":"r1","step":"apply","op":"op1"}`, "srv-9", "srv-1")
	if rr.Code != http.StatusAccepted || stub.stepCaller != "srv-9" || stub.stepReq.Op != "op1" {
		t.Fatalf("apply step = %d %s caller %q", rr.Code, rr.Body.String(), stub.stepCaller)
	}
	stub.stepResp = cluster.UpgradeStepResponse{State: cluster.UpgradeNodeStaged}
	if rr := call(h.clusterNodeUpgradeStep, http.MethodPost, "/x", `{"step":"stage"}`, "srv-9", "srv-1"); rr.Code != http.StatusOK {
		t.Fatalf("stage step = %d", rr.Code)
	}
	if rr := call(h.clusterNodeUpgradeStep, http.MethodPost, "/x", `{`, "srv-9", "srv-1"); rr.Code != http.StatusBadRequest {
		t.Fatalf("broken step = %d", rr.Code)
	}
	if rr := call(h.clusterNodeUpgradeStep, http.MethodPost, "/x", `{}`, "srv-9", "srv-2"); rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("step for another node = %d", rr.Code)
	}
	stub.stepErr = &cluster.UpgradeStepError{Status: http.StatusForbidden, Code: "not_leader", Reason: "no"}
	if rr := call(h.clusterNodeUpgradeStep, http.MethodPost, "/x", `{}`, "srv-9", "srv-1"); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "not_leader") {
		t.Fatalf("fenced step = %d %s", rr.Code, rr.Body.String())
	}
	req := internalReq(http.MethodGet, "/x?op=op7", "", "srv-9")
	req.SetPathValue("id", "srv-1")
	rr = httptest.NewRecorder()
	h.clusterNodeUpgradeStatus(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"op":"op7"`) {
		t.Fatalf("status = %d %s", rr.Code, rr.Body.String())
	}
	// Fence: only for the asking node, and only on a server.
	stub.fence = cluster.UpgradeFence{Leader: "srv-1", Term: 3}
	if rr := call(h.clusterInternalUpgradeFence, http.MethodGet, "/x?rollout=r1&node=wkr-1", "", "wkr-1", ""); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"term":3`) {
		t.Fatalf("fence = %d %s", rr.Code, rr.Body.String())
	}
	if rr := call(h.clusterInternalUpgradeFence, http.MethodGet, "/x?rollout=r1&node=wkr-2", "", "wkr-1", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("someone else's fence = %d", rr.Code)
	}
	stub.fenceErr = errors.New("no leader")
	if rr := call(h.clusterInternalUpgradeFence, http.MethodGet, "/x?rollout=r1&node=wkr-1", "", "wkr-1", ""); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("fence error = %d", rr.Code)
	}
	sum := hexSum("f")
	if rr := call(h.clusterInternalUpgradeFile, http.MethodGet, cluster.PublicInternalUpgradeFilesPath+sum, "", "wkr-1", ""); rr.Code != http.StatusOK || stub.served != "wkr-1 "+sum {
		t.Fatalf("file = %d %q", rr.Code, stub.served)
	}
	// A worker holds no rollout and serves no files.
	wh := joinHandlers(t, newWorkerStub())
	if rr := call(wh.clusterInternalUpgradeFence, http.MethodGet, "/x?node=wkr-1", "", "wkr-1", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("fence on a worker = %d", rr.Code)
	}
	if rr := call(wh.clusterInternalUpgradeFile, http.MethodGet, cluster.PublicInternalUpgradeFilesPath+sum, "", "wkr-1", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("file on a worker = %d", rr.Code)
	}
	// Single node: the peer routes answer not_cluster_mode.
	nh := joinHandlers(t, cluster.NewNoop("solo", "http://solo", ""))
	if rr := call(nh.clusterNodeUpgradeStep, http.MethodPost, "/x", `{}`, "x", "solo"); rr.Code != http.StatusConflict {
		t.Fatalf("step on a single node = %d", rr.Code)
	}
}

// workerStub steps like a worker: no Rollouts, no UpgradeFiles.
type workerStub struct {
	*cluster.Noop
}

func newWorkerStub() workerStub { return workerStub{cluster.NewNoop("wkr-1", "http://wkr-1", "")} }

func (workerStub) UpgradeStep(context.Context, string, cluster.UpgradeStepRequest) (cluster.UpgradeStepResponse, error) {
	return cluster.UpgradeStepResponse{}, nil
}
func (workerStub) UpgradeStatus(context.Context, string) cluster.UpgradeNodeStatus {
	return cluster.UpgradeNodeStatus{}
}
func (workerStub) UpgradeFenceFor(context.Context, string, string) (cluster.UpgradeFence, error) {
	return cluster.UpgradeFence{}, nil
}
