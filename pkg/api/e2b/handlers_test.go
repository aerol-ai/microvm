package e2b

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestE2BSandboxFlow(t *testing.T) {
	ctx := context.Background()
	_, st, handler := newE2BHandlerTestEnv(t)

	createBody := `{"templateID":"base","metadata":{"team":"sdk"},"timeout":120,"autoPause":true,"autoResume":{"enabled":true},"secure":true,"allow_internet_access":false}`
	createReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(createBody))
	createResp := httptest.NewRecorder()
	handler.ServeHTTP(createResp, createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body=%s", createResp.Code, http.StatusCreated, createResp.Body.String())
	}

	var created sandboxResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response error = %v", err)
	}
	if created.SandboxID == "" {
		t.Fatal("create response missing sandboxID")
	}
	if created.TemplateID != "base" {
		t.Fatalf("TemplateID = %q, want %q", created.TemplateID, "base")
	}
	if created.EnvdVersion != defaultEnvdVersion {
		t.Fatalf("EnvdVersion = %q, want %q", created.EnvdVersion, defaultEnvdVersion)
	}
	if created.EnvdAccessToken == "" {
		t.Fatal("create response missing envdAccessToken for secure sandbox")
	}

	storedMeta, err := st.GetE2BSandboxMetadata(ctx, created.SandboxID)
	if err != nil {
		t.Fatalf("GetE2BSandboxMetadata() error = %v", err)
	}
	if storedMeta.OnTimeout != "pause" || !storedMeta.AutoResume {
		t.Fatalf("unexpected stored lifecycle metadata: %+v", storedMeta)
	}
	if storedMeta.AllowInternetAccess == nil || *storedMeta.AllowInternetAccess {
		t.Fatalf("AllowInternetAccess = %+v, want false", storedMeta.AllowInternetAccess)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes/"+created.SandboxID, nil)
	getResp := httptest.NewRecorder()
	handler.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status = %d, want %d; body=%s", getResp.Code, http.StatusOK, getResp.Body.String())
	}
	var detail sandboxDetailResponse
	if err := json.NewDecoder(getResp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode get response error = %v", err)
	}
	if detail.State != "running" {
		t.Fatalf("detail.State = %q, want %q", detail.State, "running")
	}
	if detail.Lifecycle == nil || detail.Lifecycle.OnTimeout != "pause" || !detail.Lifecycle.AutoResume {
		t.Fatalf("unexpected lifecycle payload: %+v", detail.Lifecycle)
	}
	if detail.AllowInternetAccess == nil || *detail.AllowInternetAccess {
		t.Fatalf("detail.AllowInternetAccess = %+v, want false", detail.AllowInternetAccess)
	}
	if detail.Metadata["team"] != "sdk" {
		t.Fatalf("detail.Metadata = %+v, want team=sdk", detail.Metadata)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/e2b/v2/sandboxes?metadata=team%3Dsdk&state=running", nil)
	listResp := httptest.NewRecorder()
	handler.ServeHTTP(listResp, listReq)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d; body=%s", listResp.Code, http.StatusOK, listResp.Body.String())
	}
	var listed []listedSandboxResponse
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list response error = %v", err)
	}
	if len(listed) != 1 || listed[0].SandboxID != created.SandboxID {
		t.Fatalf("unexpected sandbox list: %+v", listed)
	}

	pauseReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+created.SandboxID+"/pause", nil)
	pauseResp := httptest.NewRecorder()
	handler.ServeHTTP(pauseResp, pauseReq)
	if pauseResp.Code != http.StatusNoContent {
		t.Fatalf("pause status = %d, want %d; body=%s", pauseResp.Code, http.StatusNoContent, pauseResp.Body.String())
	}

	connectReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+created.SandboxID+"/connect", strings.NewReader(`{"timeout":90}`))
	connectResp := httptest.NewRecorder()
	handler.ServeHTTP(connectResp, connectReq)
	if connectResp.Code != http.StatusOK {
		t.Fatalf("connect status = %d, want %d; body=%s", connectResp.Code, http.StatusOK, connectResp.Body.String())
	}

	getAfterConnectReq := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes/"+created.SandboxID, nil)
	getAfterConnectResp := httptest.NewRecorder()
	handler.ServeHTTP(getAfterConnectResp, getAfterConnectReq)
	if getAfterConnectResp.Code != http.StatusOK {
		t.Fatalf("get-after-connect status = %d, want %d; body=%s", getAfterConnectResp.Code, http.StatusOK, getAfterConnectResp.Body.String())
	}
	var detailAfterConnect sandboxDetailResponse
	if err := json.NewDecoder(getAfterConnectResp.Body).Decode(&detailAfterConnect); err != nil {
		t.Fatalf("decode get-after-connect response error = %v", err)
	}
	if detailAfterConnect.State != "running" {
		t.Fatalf("detailAfterConnect.State = %q, want %q", detailAfterConnect.State, "running")
	}

	timeoutReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+created.SandboxID+"/timeout", strings.NewReader(`{"timeout":30}`))
	timeoutResp := httptest.NewRecorder()
	handler.ServeHTTP(timeoutResp, timeoutReq)
	if timeoutResp.Code != http.StatusNoContent {
		t.Fatalf("timeout status = %d, want %d; body=%s", timeoutResp.Code, http.StatusNoContent, timeoutResp.Body.String())
	}
	storedMeta, err = st.GetE2BSandboxMetadata(ctx, created.SandboxID)
	if err != nil {
		t.Fatalf("GetE2BSandboxMetadata() after timeout error = %v", err)
	}
	if storedMeta.TimeoutSeconds != 30 {
		t.Fatalf("storedMeta.TimeoutSeconds = %d, want %d", storedMeta.TimeoutSeconds, 30)
	}

	snapshotReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+created.SandboxID+"/snapshots", strings.NewReader(`{"name":"team/demo"}`))
	snapshotResp := httptest.NewRecorder()
	handler.ServeHTTP(snapshotResp, snapshotReq)
	if snapshotResp.Code != http.StatusCreated {
		t.Fatalf("snapshot status = %d, want %d; body=%s", snapshotResp.Code, http.StatusCreated, snapshotResp.Body.String())
	}
	var snapshot snapshotInfoResponse
	if err := json.NewDecoder(snapshotResp.Body).Decode(&snapshot); err != nil {
		t.Fatalf("decode snapshot response error = %v", err)
	}
	if strings.Contains(snapshot.SnapshotID, "/") {
		t.Fatalf("SnapshotID = %q, want path-safe identifier", snapshot.SnapshotID)
	}
	if len(snapshot.Names) != 1 || snapshot.Names[0] != "team/demo:default" {
		t.Fatalf("snapshot.Names = %+v, want [team/demo:default]", snapshot.Names)
	}

	listSnapshotsReq := httptest.NewRequest(http.MethodGet, "/e2b/snapshots?sandboxID="+created.SandboxID, nil)
	listSnapshotsResp := httptest.NewRecorder()
	handler.ServeHTTP(listSnapshotsResp, listSnapshotsReq)
	if listSnapshotsResp.Code != http.StatusOK {
		t.Fatalf("list snapshots status = %d, want %d; body=%s", listSnapshotsResp.Code, http.StatusOK, listSnapshotsResp.Body.String())
	}
	var snapshots []snapshotInfoResponse
	if err := json.NewDecoder(listSnapshotsResp.Body).Decode(&snapshots); err != nil {
		t.Fatalf("decode snapshot list error = %v", err)
	}
	if len(snapshots) != 1 || snapshots[0].SnapshotID != snapshot.SnapshotID {
		t.Fatalf("unexpected snapshots list: %+v", snapshots)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/e2b/templates/"+snapshot.SnapshotID, nil)
	deleteResp := httptest.NewRecorder()
	handler.ServeHTTP(deleteResp, deleteReq)
	if deleteResp.Code != http.StatusNoContent {
		t.Fatalf("delete snapshot status = %d, want %d; body=%s", deleteResp.Code, http.StatusNoContent, deleteResp.Body.String())
	}
	if _, err := st.GetE2BSnapshot(ctx, snapshot.SnapshotID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected E2B snapshot metadata to be deleted, got %v", err)
	}
}

func TestCreateSandboxRejectsUnsupportedNetworkAllowOut(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","network":{"allowOut":["1.1.1.1"]}}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNotImplemented, rr.Body.String())
	}
	var resp errorResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response error = %v", err)
	}
	if resp.Code != http.StatusNotImplemented {
		t.Fatalf("resp.Code = %d, want %d", resp.Code, http.StatusNotImplemented)
	}
}

type fakeE2BRuntime struct {
	mu            sync.Mutex
	states        map[string]*models.SandboxRuntimeState
	removedImages []string
	imageSeq      int
	ipSeq         int
}

func newFakeE2BRuntime() *fakeE2BRuntime {
	return &fakeE2BRuntime{
		states: make(map[string]*models.SandboxRuntimeState),
		ipSeq:  20,
	}
}

func (f *fakeE2BRuntime) Create(_ context.Context, _ models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ipSeq++
	state := &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: "ctr-" + sandboxID,
		ContainerIP: fmt.Sprintf("10.42.0.%d", f.ipSeq),
		Status:      models.SandboxStatusStarted,
	}
	f.states[sandboxID] = cloneRuntimeState(state)
	return cloneRuntimeState(state), nil
}

func (f *fakeE2BRuntime) Start(_ context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lookup(containerRef)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", containerRef)
	}
	state.Status = models.SandboxStatusStarted
	return cloneRuntimeState(state), nil
}

func (f *fakeE2BRuntime) Stop(_ context.Context, containerRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lookup(containerRef)
	if !ok {
		return fmt.Errorf("sandbox %q not found", containerRef)
	}
	state.Status = models.SandboxStatusStopped
	return nil
}

func (f *fakeE2BRuntime) Destroy(_ context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.states, sandbox.ID)
	return nil
}

func (f *fakeE2BRuntime) CreateSnapshot(_ context.Context, _ string, imageRef string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.imageSeq++
	return fmt.Sprintf("sha256:%s-%03d", sanitizeSnapshotID(imageRef), f.imageSeq), nil
}

func (f *fakeE2BRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}

func (f *fakeE2BRuntime) Inspect(_ context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lookup(containerRef)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", containerRef)
	}
	return cloneRuntimeState(state), nil
}

func (f *fakeE2BRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := make(map[string]*models.SandboxRuntimeState, len(f.states))
	for sandboxID, state := range f.states {
		items[sandboxID] = cloneRuntimeState(state)
	}
	return items, nil
}

func (f *fakeE2BRuntime) Ping(context.Context) error { return nil }

func (f *fakeE2BRuntime) RemoveImage(_ context.Context, imageRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removedImages = append(f.removedImages, imageRef)
	return nil
}

func (f *fakeE2BRuntime) PushAllowedPorts(context.Context, string, string, []int) error { return nil }
func (f *fakeE2BRuntime) ClearNetworkRules(string) error                                { return nil }
func (f *fakeE2BRuntime) ApplyNetworkBlockAll(string) error                             { return nil }

func (f *fakeE2BRuntime) lookup(containerRef string) (*models.SandboxRuntimeState, bool) {
	if state, ok := f.states[containerRef]; ok {
		return state, true
	}
	for _, state := range f.states {
		if state.ContainerID == containerRef {
			return state, true
		}
	}
	return nil, false
}

func cloneRuntimeState(state *models.SandboxRuntimeState) *models.SandboxRuntimeState {
	if state == nil {
		return nil
	}
	cloned := *state
	return &cloned
}

func sanitizeSnapshotID(value string) string {
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return value
}

func newE2BHandlerTestEnv(t *testing.T) (*service.Service, *store.Store, http.Handler) {
	t.Helper()
	t.Setenv("SB_E2B_TEMPLATE_MAP_JSON", `{"base":"ubuntu:22.04"}`)

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mountManager, err := mounts.New(logger, mounts.Config{
		RootDir:     filepath.Join(dir, "mounts"),
		CredDir:     filepath.Join(dir, "creds"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New() error = %v", err)
	}
	t.Cleanup(mountManager.Close)

	cipher, err := secrets.NewCipher("", filepath.Join(dir, "cipher.key"))
	if err != nil {
		t.Fatalf("secrets.NewCipher() error = %v", err)
	}

	runtime := newFakeE2BRuntime()
	cfg := config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280}
	svc := service.New(cfg, logger, st, runtime, nil, caddy.New(cfg), cipher, mountManager, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(next http.Handler) http.Handler {
			return next
		},
	})
	return svc, st, mux
}
