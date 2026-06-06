package e2b

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"path/filepath"
	"strconv"
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

	storedMeta, err := loadE2BSandboxMeta(ctx, st, created.SandboxID)
	if err != nil {
		t.Fatalf("loadE2BSandboxMeta() error = %v", err)
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
	storedMeta, err = loadE2BSandboxMeta(ctx, st, created.SandboxID)
	if err != nil {
		t.Fatalf("loadE2BSandboxMeta() after timeout error = %v", err)
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
	if _, err := st.GetSnapshotAlias(ctx, snapshot.SnapshotID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected E2B snapshot alias to be deleted, got %v", err)
	}
}

// loadE2BSandboxMeta is the test-side equivalent of the old per-facade
// GetE2BSandboxMetadata: read the native sandbox row plus its E2B compat
// blob and combine them through the facade's own meta builder, so contract
// assertions stay against the same in-memory shape they did before.
func loadE2BSandboxMeta(ctx context.Context, st *store.Store, sandboxID string) (sandboxMeta, error) {
	sandbox, err := st.Get(ctx, sandboxID)
	if err != nil {
		return sandboxMeta{}, err
	}
	state, err := st.GetCompatState(ctx, sandboxID, models.FacadeE2B)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return sandboxMeta{}, err
	}
	return sandboxMetaFromState(state, sandbox)
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

func TestCreateSandboxIdempotentReplay(t *testing.T) {
	runtime := newFakeE2BRuntime()
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})

	body := `{"templateID":"base","metadata":{"team":"sdk"},"timeout":120}`
	firstReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
	firstResp := httptest.NewRecorder()
	handler.ServeHTTP(firstResp, firstReq)
	if firstResp.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want %d; body=%s", firstResp.Code, http.StatusCreated, firstResp.Body.String())
	}
	var first sandboxResponse
	if err := json.NewDecoder(firstResp.Body).Decode(&first); err != nil {
		t.Fatalf("decode first create response error = %v", err)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
	secondResp := httptest.NewRecorder()
	handler.ServeHTTP(secondResp, secondReq)
	if secondResp.Code != http.StatusCreated {
		t.Fatalf("second create status = %d, want %d; body=%s", secondResp.Code, http.StatusCreated, secondResp.Body.String())
	}
	var second sandboxResponse
	if err := json.NewDecoder(secondResp.Body).Decode(&second); err != nil {
		t.Fatalf("decode second create response error = %v", err)
	}
	if second.SandboxID != first.SandboxID {
		t.Fatalf("second SandboxID = %q, want %q", second.SandboxID, first.SandboxID)
	}
	runtime.mu.Lock()
	createHits := runtime.createHits
	runtime.mu.Unlock()
	if createHits != 1 {
		t.Fatalf("runtime create hits = %d, want 1", createHits)
	}
}

func TestWaitForCreateReplayIgnoresExpiredReadyRecord(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newE2BHandlerTestEnv(t)
	now := time.Now().UTC().Add(-time.Minute).Round(0)
	fingerprint := "fp:expired-ready"
	sandbox := &models.Sandbox{
		ID:               "sb-expired-ready",
		Image:            "ubuntu:22.04",
		Status:           models.SandboxStatusStarted,
		PublicURL:        "https://sb-expired-ready.example.com",
		ContainerID:      "container-sb-expired-ready",
		ContainerIP:      "10.0.0.10",
		CPU:              2,
		MemoryMB:         2048,
		DiskGB:           20,
		OSUser:           "root",
		Env:              map[string]string{},
		ToolboxEnabled:   true,
		ContainerCommand: []string{"bash"},
		CreatedAt:        now,
		UpdatedAt:        now,
		LastActiveAt:     now,
		Runtime:          models.RuntimeGvisor,
	}
	if err := st.Create(ctx, sandbox); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, acquired, err := st.ClaimIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, now, time.Second); err != nil {
		t.Fatalf("ClaimIdempotentRequest() error = %v", err)
	} else if !acquired {
		t.Fatal("expected initial create request claim to acquire")
	}
	if err := st.CompleteIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint, sandbox.ID, now, time.Second); err != nil {
		t.Fatalf("CompleteIdempotentRequest() error = %v", err)
	}

	h := newHandlers(Deps{Service: svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	_, _, replayed, err := h.waitForCreateReplay(ctx, fingerprint)
	if err != nil {
		t.Fatalf("waitForCreateReplay() error = %v", err)
	}
	if replayed {
		t.Fatal("expected expired ready record not to replay")
	}
	if _, err := st.GetIdempotentRequest(ctx, idempotencyScopeCreate, fingerprint); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected expired ready record to be cleared, got %v", err)
	}
}

func TestCreateSnapshotWithoutNameIsIdempotent(t *testing.T) {
	runtime := newFakeE2BRuntime()
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})

	createReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base"}`))
	createResp := httptest.NewRecorder()
	handler.ServeHTTP(createResp, createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body=%s", createResp.Code, http.StatusCreated, createResp.Body.String())
	}
	var created sandboxResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response error = %v", err)
	}

	firstReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+created.SandboxID+"/snapshots", strings.NewReader(`{}`))
	firstResp := httptest.NewRecorder()
	handler.ServeHTTP(firstResp, firstReq)
	if firstResp.Code != http.StatusCreated {
		t.Fatalf("first snapshot status = %d, want %d; body=%s", firstResp.Code, http.StatusCreated, firstResp.Body.String())
	}
	var first snapshotInfoResponse
	if err := json.NewDecoder(firstResp.Body).Decode(&first); err != nil {
		t.Fatalf("decode first snapshot response error = %v", err)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+created.SandboxID+"/snapshots", strings.NewReader(`{}`))
	secondResp := httptest.NewRecorder()
	handler.ServeHTTP(secondResp, secondReq)
	if secondResp.Code != http.StatusCreated {
		t.Fatalf("second snapshot status = %d, want %d; body=%s", secondResp.Code, http.StatusCreated, secondResp.Body.String())
	}
	var second snapshotInfoResponse
	if err := json.NewDecoder(secondResp.Body).Decode(&second); err != nil {
		t.Fatalf("decode second snapshot response error = %v", err)
	}
	if second.SnapshotID != first.SnapshotID {
		t.Fatalf("second SnapshotID = %q, want %q", second.SnapshotID, first.SnapshotID)
	}
	if len(second.Names) != 1 || second.Names[0] != defaultSnapshotName(created.SandboxID) {
		t.Fatalf("second.Names = %+v, want [%q]", second.Names, defaultSnapshotName(created.SandboxID))
	}

	runtime.mu.Lock()
	imageSeq := runtime.imageSeq
	runtime.mu.Unlock()
	if imageSeq != 1 {
		t.Fatalf("runtime snapshot creates = %d, want 1", imageSeq)
	}
}

func TestRuntimeProxyRewritesToEnvdToolboxSurface(t *testing.T) {
	toolboxRequests := make(chan *http.Request, 1)
	toolboxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		toolboxRequests <- r.Clone(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	}))
	defer toolboxServer.Close()

	parsedURL, err := neturl.Parse(toolboxServer.URL)
	if err != nil {
		t.Fatalf("parse toolbox url error = %v", err)
	}
	host, portText, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		t.Fatalf("split toolbox host error = %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse toolbox port error = %v", err)
	}

	runtime := newFakeE2BRuntime()
	runtime.containerIP = host
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: port})

	createReq := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","secure":true}`))
	createResp := httptest.NewRecorder()
	handler.ServeHTTP(createResp, createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body=%s", createResp.Code, http.StatusCreated, createResp.Body.String())
	}
	var created sandboxResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response error = %v", err)
	}

	runtimeReq := httptest.NewRequest(http.MethodGet, "/e2b/runtime/health", nil)
	runtimeReq.Header.Set("E2b-Sandbox-Id", created.SandboxID)
	runtimeReq.Header.Set("X-Access-Token", created.EnvdAccessToken)
	runtimeReq.Header.Set("Authorization", "Basic dXNlcjo=")
	runtimeResp := httptest.NewRecorder()
	handler.ServeHTTP(runtimeResp, runtimeReq)
	if runtimeResp.Code != http.StatusOK {
		t.Fatalf("runtime status = %d, want %d; body=%s", runtimeResp.Code, http.StatusOK, runtimeResp.Body.String())
	}

	select {
	case forwarded := <-toolboxRequests:
		if forwarded.URL.Path != "/envd/health" {
			t.Fatalf("forwarded path = %q, want %q", forwarded.URL.Path, "/envd/health")
		}
		if forwarded.Header.Get("Authorization") == "" || !strings.HasPrefix(forwarded.Header.Get("Authorization"), "Bearer ") {
			t.Fatalf("forwarded Authorization = %q, want Bearer token", forwarded.Header.Get("Authorization"))
		}
		if forwarded.Header.Get("X-E2B-User-Authorization") != "Basic dXNlcjo=" {
			t.Fatalf("forwarded X-E2B-User-Authorization = %q", forwarded.Header.Get("X-E2B-User-Authorization"))
		}
		if forwarded.Header.Get("X-E2B-Sandbox-Id") != created.SandboxID {
			t.Fatalf("forwarded X-E2B-Sandbox-Id = %q, want %q", forwarded.Header.Get("X-E2B-Sandbox-Id"), created.SandboxID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected toolbox request to be forwarded")
	}
}

type fakeE2BRuntime struct {
	mu                sync.Mutex
	states            map[string]*models.SandboxRuntimeState
	removedImages     []string
	imageSeq          int
	ipSeq             int
	createHits        int
	containerIP       string
	errCreate         error
	errStart          error
	errStop           error
	errDestroy        error
	errRemoveImage    error
	errCreateSnapshot error
	onCreateChan      chan struct{}
	blockCreate       chan struct{}
}

func newFakeE2BRuntime() *fakeE2BRuntime {
	return &fakeE2BRuntime{
		states: make(map[string]*models.SandboxRuntimeState),
		ipSeq:  20,
	}
}

func (f *fakeE2BRuntime) Create(_ context.Context, _ models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if f.onCreateChan != nil {
		select {
		case f.onCreateChan <- struct{}{}:
		default:
		}
	}
	if f.blockCreate != nil {
		<-f.blockCreate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errCreate != nil {
		return nil, f.errCreate
	}
	f.ipSeq++
	f.createHits++
	containerIP := f.containerIP
	if containerIP == "" {
		containerIP = fmt.Sprintf("10.42.0.%d", f.ipSeq)
	}
	state := &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: "ctr-" + sandboxID,
		ContainerIP: containerIP,
		Status:      models.SandboxStatusStarted,
	}
	f.states[sandboxID] = cloneRuntimeState(state)
	return cloneRuntimeState(state), nil
}

func (f *fakeE2BRuntime) Start(_ context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errStart != nil {
		return nil, f.errStart
	}
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
	if f.errStop != nil {
		return f.errStop
	}
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
	if f.errDestroy != nil {
		return f.errDestroy
	}
	delete(f.states, sandbox.ID)
	return nil
}

func (f *fakeE2BRuntime) CreateSnapshot(_ context.Context, _ string, imageRef string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errCreateSnapshot != nil {
		return "", f.errCreateSnapshot
	}
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
	if f.errRemoveImage != nil {
		return f.errRemoveImage
	}
	f.removedImages = append(f.removedImages, imageRef)
	return nil
}

func (f *fakeE2BRuntime) PushAllowedPorts(context.Context, string, string, []int) error { return nil }
func (f *fakeE2BRuntime) ClearNetworkRules(string) error                                { return nil }
func (f *fakeE2BRuntime) ApplyNetworkBlockAll(string) error                             { return nil }
func (f *fakeE2BRuntime) ApplyNetworkBlockIngress(string) error                         { return nil }
func (f *fakeE2BRuntime) ClearNetworkBlockIngress(string) error                         { return nil }
func (f *fakeE2BRuntime) ClearNetworkBlockEgress(string) error                          { return nil }

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
	return newE2BHandlerTestEnvWithRuntime(t, newFakeE2BRuntime(), config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})
}

func newE2BHandlerTestEnvWithRuntime(t *testing.T, runtime *fakeE2BRuntime, cfg config.Config) (*service.Service, *store.Store, http.Handler) {
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

// TestE2BCreateAutoResumeDoesNotEnableServerless: per the plan, the
// existing autoResume semantics (reconnect to a paused sandbox at
// connect time) must NOT auto-enable AerolVM-native serverless.
// Lifecycle.Serverless stays false unless the caller explicitly
// opts in via the aerolvm.serverless metadata key.
func TestE2BCreateAutoResumeDoesNotEnableServerless(t *testing.T) {
	ctx := context.Background()
	_, st, handler := newE2BHandlerTestEnv(t)

	body := `{"templateID":"base","timeout":120,"autoPause":true,"autoResume":{"enabled":true}}`
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var created sandboxResponse
	if err := json.NewDecoder(rr.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	sb, err := st.Get(ctx, created.SandboxID)
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if sb.Lifecycle.Serverless {
		t.Fatalf("autoResume implicitly enabled Lifecycle.Serverless; must require explicit metadata opt-in")
	}
}

// TestE2BCreateServerlessMetadataOptsIn: explicit
// metadata["aerolvm.serverless"]="true" flips Lifecycle.Serverless
// on, and the timeout is rewritten into StopIfIdleFor (the only
// shape the native store accepts alongside Serverless=true).
func TestE2BCreateServerlessMetadataOptsIn(t *testing.T) {
	ctx := context.Background()
	_, st, handler := newE2BHandlerTestEnv(t)

	body := `{"templateID":"base","timeout":120,"autoPause":true,"autoResume":{"enabled":true},"metadata":{"aerolvm.serverless":"true"}}`
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var created sandboxResponse
	if err := json.NewDecoder(rr.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	sb, err := st.Get(ctx, created.SandboxID)
	if err != nil {
		t.Fatalf("get sandbox: %v", err)
	}
	if !sb.Lifecycle.Serverless {
		t.Fatalf("Lifecycle.Serverless = false despite aerolvm.serverless=true metadata")
	}
	if sb.Lifecycle.StopIfIdleFor != 120*time.Second {
		t.Fatalf("StopIfIdleFor = %v, want 120s (translated from timeout)", sb.Lifecycle.StopIfIdleFor)
	}
	if sb.Lifecycle.StopAtAge != 0 || sb.Lifecycle.DestroyAtAge != 0 {
		t.Fatalf("serverless lifecycle must clear StopAtAge/DestroyAtAge; got Stop=%v Destroy=%v",
			sb.Lifecycle.StopAtAge, sb.Lifecycle.DestroyAtAge)
	}
}

// TestE2BServerlessMetadataAcceptsTruthyVariants documents the
// truthy-value contract for the opt-in flag — case-insensitive
// "true" / "1" / "yes" / "on" all enable serverless, everything
// else (including the literal "false") leaves it disabled.
func TestE2BServerlessMetadataAcceptsTruthyVariants(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"on", true},
		{"false", false},
		{"0", false},
		{"", false},
		{"maybe", false},
	}
	for _, tc := range cases {
		got := serverlessFromMetadata(map[string]string{metadataKeyServerless: tc.value})
		if got != tc.want {
			t.Errorf("serverlessFromMetadata(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
