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
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// apiRecordingRuntime is a minimal runtime stub for v1 handler tests that
// need CreateSandbox/CreateSandboxWithID or DestroySandbox to succeed.
type apiRecordingRuntime struct {
	noopRuntime
	createErr    error
	destroyIDs   []string
	destroyErr   error
	createCalls  int
	lastCreateID string
}

func (r *apiRecordingRuntime) Create(_ context.Context, _ models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.createCalls++
	r.lastCreateID = sandboxID
	if r.createErr != nil {
		return nil, r.createErr
	}
	return &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: "ctr-" + sandboxID,
		ContainerIP: "10.0.0.2",
		Status:      models.SandboxStatusStarted,
	}, nil
}

func (r *apiRecordingRuntime) Destroy(_ context.Context, sandbox *models.Sandbox) error {
	if sandbox != nil {
		r.destroyIDs = append(r.destroyIDs, sandbox.ID)
	}
	return r.destroyErr
}

func (r *apiRecordingRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return map[string]*models.SandboxRuntimeState{}, nil
}

func (r *apiRecordingRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	return nil
}

func (r *apiRecordingRuntime) Start(_ context.Context, sandboxID string) (*models.SandboxRuntimeState, error) {
	return &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: "ctr-" + sandboxID,
		ContainerIP: "10.0.0.5",
		Status:      models.SandboxStatusStarted,
	}, nil
}

func (r *apiRecordingRuntime) Stop(_ context.Context, _ string) error { return nil }

func (r *apiRecordingRuntime) ApplyNetworkBlockAll(string) error     { return nil }
func (r *apiRecordingRuntime) ClearNetworkBlockEgress(string) error  { return nil }
func (r *apiRecordingRuntime) ClearNetworkBlockIngress(string) error { return nil }

type promoteStubCluster struct {
	*cluster.Noop
	recordCalls []string
	recordErr   error
	cancelCalls []string
	cancelErr   error
	deleteCalls []string
	deleteErr   error
}

func (c *promoteStubCluster) RecordPlacement(_ context.Context, id string, _ *models.CreateSandboxRequest, _ cluster.PlacementSecrets) error {
	c.recordCalls = append(c.recordCalls, id)
	return c.recordErr
}

func (c *promoteStubCluster) CancelReservation(_ context.Context, id string) error {
	c.cancelCalls = append(c.cancelCalls, id)
	return c.cancelErr
}

func (c *promoteStubCluster) DeletePlacement(_ context.Context, id string) error {
	c.deleteCalls = append(c.deleteCalls, id)
	return c.deleteErr
}

func newClusterCreateHarness(t *testing.T, rt *apiRecordingRuntime, stub cluster.Client) (*handlers, *storepkg.Store) {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir: filepath.Join(t.TempDir(), "mounts"),
		CredDir: filepath.Join(t.TempDir(), "cred"),
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		Runtime:           models.RuntimeDocker,
		ToolboxPort:       4321,
		EnableCaddy:       false,
		HTTPClientTimeout: time.Second,
	}
	caddyClient := caddy.New(cfg)
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)
	svc := service.New(cfg, logger, st, rt, nil, caddyClient, nil, mgr, admitter)
	svc.AttachCluster(stub)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, st
}

func newClusterCreateHarnessWithCipher(t *testing.T, rt *apiRecordingRuntime, stub cluster.Client) (*handlers, *storepkg.Store) {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir: filepath.Join(t.TempDir(), "mounts"),
		CredDir: filepath.Join(t.TempDir(), "cred"),
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	ciph, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "secrets.key"))
	if err != nil {
		t.Fatalf("secrets.NewCipher: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		Runtime:           models.RuntimeDocker,
		ToolboxPort:       4321,
		EnableCaddy:       false,
		HTTPClientTimeout: time.Second,
	}
	caddyClient := caddy.New(cfg)
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)
	svc := service.New(cfg, logger, st, rt, nil, caddyClient, ciph, mgr, admitter)
	svc.AttachCluster(stub)
	return &handlers{deps: Deps{Service: svc, Logger: logger}}, st
}

func TestCreateSandboxOnSelectedNode_PromoteSuccess(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-reserved")

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if rt.lastCreateID != "sb-reserved" {
		t.Fatalf("create id = %q, want sb-reserved", rt.lastCreateID)
	}
	if len(stub.recordCalls) != 1 || stub.recordCalls[0] != "sb-reserved" {
		t.Fatalf("RecordPlacement calls = %+v, want [sb-reserved]", stub.recordCalls)
	}
}

func TestCreateSandboxOnSelectedNode_CreateFailureCancelsReservation(t *testing.T) {
	rt := &apiRecordingRuntime{createErr: errors.New("runtime create failed")}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-fail")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(stub.cancelCalls) != 1 || stub.cancelCalls[0] != "sb-fail" {
		t.Fatalf("CancelReservation calls = %+v, want [sb-fail]", stub.cancelCalls)
	}
}

func TestCreateSandboxOnSelectedNode_RecordPlacementFailureRollsBack(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		recordErr: errors.New("raft commit failed"),
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-promote-fail")

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if len(rt.destroyIDs) != 1 || rt.destroyIDs[0] != "sb-promote-fail" {
		t.Fatalf("destroy ids = %+v, want rollback destroy", rt.destroyIDs)
	}
	if len(stub.cancelCalls) != 1 || stub.cancelCalls[0] != "sb-promote-fail" {
		t.Fatalf("CancelReservation calls = %+v, want [sb-promote-fail]", stub.cancelCalls)
	}
}

func TestCreateSandboxOnSelectedNode_NormalizeRuntimeError(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{
		Image: "alpine:3.20", Runtime: models.RuntimeDocker, TemplateID: "tpl-x",
	}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if rt.createCalls != 0 {
		t.Fatalf("Create calls = %d, want 0 on validation failure", rt.createCalls)
	}
}

func TestCreateSandboxOnSelectedNode_NilClusterUsesCreateSandbox(t *testing.T) {
	h := newHandlerWithStore(t)
	h.deps.Service.ClearClusterForTest()
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, models.CreateSandboxRequest{}, "")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSandboxOnSelectedNode_SelfLocalWithoutReservation(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "")

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if len(stub.recordCalls) != 1 {
		t.Fatalf("RecordPlacement calls = %+v, want one promote", stub.recordCalls)
	}
}

func TestCreateSandboxOnSelectedNode_PromoteWithRegistrySecrets(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarnessWithCipher(t, rt, stub)

	req := models.CreateSandboxRequest{
		Image: "private.example.com/app:latest",
		Registry: &models.RegistryAuth{
			Server: "private.example.com", Username: "u", Password: "secret",
		},
	}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-secrets")

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if len(stub.recordCalls) != 1 || stub.recordCalls[0] != "sb-secrets" {
		t.Fatalf("RecordPlacement calls = %+v, want [sb-secrets]", stub.recordCalls)
	}
}

func TestCreateSandboxOnSelectedNode_RecordPlacementGenericError(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		recordErr: errors.New("raft unavailable"),
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-raft-fail")

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if len(rt.destroyIDs) != 1 || len(stub.cancelCalls) != 1 {
		t.Fatalf("destroy=%v cancel=%v, want rollback + cancel reservation", rt.destroyIDs, stub.cancelCalls)
	}
}

func TestCreateSandboxOnSelectedNode_RecordPlacementNameConflict(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		recordErr: cluster.ErrNameConflict,
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "")

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rr.Code, rr.Body.String())
	}
	if len(rt.destroyIDs) != 1 {
		t.Fatalf("destroy ids = %+v, want rollback destroy", rt.destroyIDs)
	}
}

func TestClusterCreateWrap_NilClusterUsesCreateSandbox(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	h.deps.Service.ClearClusterForTest()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	h.clusterCreateWrap(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
}

func TestClusterCreateWrap_ForwardedSelfTargetPromotes(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	req.Header.Set(clusterCreateTargetHeader, "node-a")
	req.Header.Set(clusterCreateIDHeader, "sb-fwd-self")
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.CreateSandboxResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Sandbox.ID != "sb-fwd-self" {
		t.Fatalf("sandbox id = %q, want sb-fwd-self", resp.Sandbox.ID)
	}
}

func TestClusterCreateWrap_SelfWinsAfterReserve(t *testing.T) {
	rt := &apiRecordingRuntime{}
	fake := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		target: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
	}
	h, _ := newClusterCreateHarness(t, rt, fake)

	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if len(fake.reserveCalls) != 1 {
		t.Fatalf("reserveCalls = %d, want 1", len(fake.reserveCalls))
	}
	if rt.createCalls != 1 {
		t.Fatalf("createCalls = %d, want 1", rt.createCalls)
	}
}

func TestCreateSandboxOnSelectedNode_InvalidImageDistribution(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	req.ApplyImageDistribution(models.ImageDistributionMetadata{Mode: "not-a-real-mode"})
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-bad-mode")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if rt.createCalls != 0 {
		t.Fatalf("createCalls = %d, want 0 on normalize failure", rt.createCalls)
	}
}

func TestCreateSandboxOnSelectedNode_InvalidFailover(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{
		Image:    "e2b/sb-local:default",
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	req.ApplyImageDistribution(models.ImageDistributionMetadata{Mode: models.ImageDistributionLocalOnly})
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSandboxOnSelectedNode_CreateFailureCancelReservationError(t *testing.T) {
	rt := &apiRecordingRuntime{createErr: errors.New("runtime create failed")}
	stub := &promoteStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		cancelErr: errors.New("cancel failed"),
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-cancel-fail")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if len(stub.cancelCalls) != 1 {
		t.Fatalf("CancelReservation calls = %+v, want one attempt", stub.cancelCalls)
	}
}

func TestCreateSandboxOnSelectedNode_RecordPlacementDestroyAndCancelErrors(t *testing.T) {
	rt := &apiRecordingRuntime{destroyErr: errors.New("destroy failed")}
	stub := &promoteStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		recordErr: errors.New("raft commit failed"),
		cancelErr: errors.New("cancel failed"),
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-promote-rollback-fail")

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if len(stub.cancelCalls) != 1 {
		t.Fatalf("CancelReservation calls = %+v, want one attempt", stub.cancelCalls)
	}
}

func TestCreateSandboxOnSelectedNode_NameConflictOnPromote(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		recordErr: cluster.ErrNameConflict,
	}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	rr := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	h.createSandboxOnSelectedNode(rr, httpReq, req, "sb-name-conflict")

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rr.Code, rr.Body.String())
	}
	if len(rt.destroyIDs) != 1 {
		t.Fatalf("destroy ids = %+v, want rollback destroy", rt.destroyIDs)
	}
}

func TestNormalizeCreateRuntimeForPlacement_NilRequest(t *testing.T) {
	if err := normalizeCreateRuntimeForPlacement(nil); err != nil {
		t.Fatalf("nil req: %v", err)
	}
}

func TestNormalizeCreateRuntimeForPlacement_TemplateImpliesFirecracker(t *testing.T) {
	req := models.CreateSandboxRequest{Image: "alpine", TemplateID: " tpl-fc "}
	if err := normalizeCreateRuntimeForPlacement(&req); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if req.Runtime != models.RuntimeFirecracker || req.TemplateID != "tpl-fc" {
		t.Fatalf("req = %+v, want firecracker runtime and trimmed template", req)
	}
}

func TestClusterDestroyWrap_SuccessAndDeletePlacementWarn(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		deleteErr: errors.New("fsm delete failed"),
	}
	h, st := newClusterCreateHarness(t, rt, stub)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-destroy", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-sb-destroy", ContainerIP: "10.0.0.9",
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/v1/sandboxes/sb-destroy", nil)
	req.SetPathValue("id", "sb-destroy")
	rr := httptest.NewRecorder()
	h.clusterDestroyWrap(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
	if len(rt.destroyIDs) != 1 || rt.destroyIDs[0] != "sb-destroy" {
		t.Fatalf("destroy ids = %+v, want [sb-destroy]", rt.destroyIDs)
	}
	if len(stub.deleteCalls) != 1 || stub.deleteCalls[0] != "sb-destroy" {
		t.Fatalf("DeletePlacement calls = %+v, want [sb-destroy]", stub.deleteCalls)
	}
}
