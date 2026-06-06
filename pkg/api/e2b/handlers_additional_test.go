package e2b

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestE2BCreateSandboxNotImplemented(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)

	cases := []struct {
		name string
		body string
	}{
		{"mcp", `{"templateID":"base","mcp":{}}`},
		{"volumeMounts", `{"templateID":"base","volumeMounts":[{"name":"vol"}]}`},
		{"networkAllowOut", `{"templateID":"base","network":{"allowOut":["1.1.1.1"]}}`},
		{"networkDenyOut", `{"templateID":"base","network":{"denyOut":["1.1.1.1"]}}`},
		{"networkAllowPublicTraffic", `{"templateID":"base","network":{"allowPublicTraffic":false}}`},
		{"networkMaskRequestHost", `{"templateID":"base","network":{"maskRequestHost":"host"}}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusNotImplemented {
				t.Fatalf("expected 501, got %d for %s", rr.Code, tc.name)
			}
		})
	}
}

func TestE2BCreateSandboxInvalidTimeout(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","timeout":0}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","timeout":-10}`))
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr2.Code)
	}
}

func TestE2BDeleteSandboxFails(t *testing.T) {
	runtime := newFakeE2BRuntime()
	runtime.errDestroy = errors.New("injected destroy error")
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})

	id := createE2BSandbox(t, handler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/e2b/sandboxes/"+id, nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body = %s", rr.Code, rr.Body.String())
	}
}

func TestE2BConnectSandboxInvalidStatus(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	// Update status to creating (which is invalid for connect)
	if err := st.UpdateStatus(context.Background(), id, models.SandboxStatusCreating, ""); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/connect", strings.NewReader(`{"timeout":90}`)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d; body = %s", rr.Code, rr.Body.String())
	}
}

func TestE2BConnectSandboxStartFails(t *testing.T) {
	runtime := newFakeE2BRuntime()
	runtime.errStart = errors.New("injected start error")
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})

	id := createE2BSandbox(t, handler)

	// Pause sandbox first
	rrPause := httptest.NewRecorder()
	handler.ServeHTTP(rrPause, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/pause", nil))
	if rrPause.Code != http.StatusNoContent {
		t.Fatalf("pause got status = %d", rrPause.Code)
	}

	// Try to connect (which attempts to start the paused/stopped sandbox)
	rrConnect := httptest.NewRecorder()
	handler.ServeHTTP(rrConnect, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/connect", strings.NewReader(`{"timeout":90}`)))
	if rrConnect.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body = %s", rrConnect.Code, rrConnect.Body.String())
	}
}

func TestE2BStopSandboxFails(t *testing.T) {
	runtime := newFakeE2BRuntime()
	runtime.errStop = errors.New("injected stop error")
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})

	id := createE2BSandbox(t, handler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/pause", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body = %s", rr.Code, rr.Body.String())
	}
}

func TestE2BDeleteSnapshotFails(t *testing.T) {
	runtime := newFakeE2BRuntime()
	runtime.errRemoveImage = errors.New("injected remove image error")
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})

	id := createE2BSandbox(t, handler)

	rrSnap := httptest.NewRecorder()
	handler.ServeHTTP(rrSnap, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"test-snap"}`)))
	if rrSnap.Code != http.StatusCreated {
		t.Fatalf("snapshot status = %d", rrSnap.Code)
	}

	var snap snapshotInfoResponse
	if err := json.NewDecoder(rrSnap.Body).Decode(&snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}

	rrDel := httptest.NewRecorder()
	handler.ServeHTTP(rrDel, httptest.NewRequest(http.MethodDelete, "/e2b/templates/"+snap.SnapshotID, nil))
	if rrDel.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body = %s", rrDel.Code, rrDel.Body.String())
	}
}

func TestE2BCreateSnapshotNameConflict(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)

	// Create Sandbox 1
	id1 := createE2BSandbox(t, handler)

	// Create Sandbox 2 (with different timeout to get a different sandbox ID)
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","timeout":121}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("second create status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var created2 sandboxResponse
	if err := json.NewDecoder(rr.Body).Decode(&created2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	id2 := created2.SandboxID

	if id1 == id2 {
		t.Fatal("expected sandbox IDs to be different")
	}

	// Create snapshot on Sandbox 1
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id1+"/snapshots", strings.NewReader(`{"name":"snap-dup"}`)))
	if rr1.Code != http.StatusCreated {
		t.Fatalf("first snapshot status = %d, body = %s", rr1.Code, rr1.Body.String())
	}

	// Create snapshot with SAME name on Sandbox 2 -> conflict
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id2+"/snapshots", strings.NewReader(`{"name":"snap-dup"}`)))
	if rr2.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d; body = %s", rr2.Code, rr2.Body.String())
	}
}

func TestE2BCreateSandboxConcurrencyReplay(t *testing.T) {
	runtime := newFakeE2BRuntime()
	runtime.onCreateChan = make(chan struct{}, 1)
	runtime.blockCreate = make(chan struct{})

	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})

	body := `{"templateID":"base","timeout":120}`

	firstErrChan := make(chan error, 1)
	var firstResp sandboxResponse
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			firstErrChan <- fmt.Errorf("first create status = %d, body = %s", rr.Code, rr.Body.String())
			return
		}
		if err := json.NewDecoder(rr.Body).Decode(&firstResp); err != nil {
			firstErrChan <- err
			return
		}
		firstErrChan <- nil
	}()

	// Wait until the first request hits runtime.Create
	select {
	case <-runtime.onCreateChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first request to call Create")
	}

	// Start the second request
	secondErrChan := make(chan error, 1)
	var secondResp sandboxResponse
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			secondErrChan <- fmt.Errorf("second create status = %d, body = %s", rr.Code, rr.Body.String())
			return
		}
		if err := json.NewDecoder(rr.Body).Decode(&secondResp); err != nil {
			secondErrChan <- err
			return
		}
		secondErrChan <- nil
	}()

	// Give the second request a moment to start and call waitForCreateReplay, triggering the poll timer
	time.Sleep(400 * time.Millisecond)

	// Now unblock the first request
	close(runtime.blockCreate)

	// Wait for both to complete
	if err := <-firstErrChan; err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	if err := <-secondErrChan; err != nil {
		t.Fatalf("second request failed: %v", err)
	}

	if firstResp.SandboxID == "" || secondResp.SandboxID == "" {
		t.Fatal("empty sandbox IDs returned")
	}
	if firstResp.SandboxID != secondResp.SandboxID {
		t.Fatalf("expected identical sandbox IDs, got %q and %q", firstResp.SandboxID, secondResp.SandboxID)
	}
}

func TestE2BCreateSandboxStaleIdempotentRecord(t *testing.T) {
	ctx := context.Background()
	runtime := newFakeE2BRuntime()
	_, st, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})

	body := `{"templateID":"base","timeout":120}`
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var first sandboxResponse
	if err := json.NewDecoder(rr.Body).Decode(&first); err != nil {
		t.Fatalf("decode first: %v", err)
	}

	// Manually delete the sandbox from store, keeping the idempotency record intact.
	if err := st.Delete(ctx, first.SandboxID); err != nil {
		t.Fatalf("failed to delete sandbox: %v", err)
	}

	// Requesting creation again with same parameters should notice the missing sandbox,
	// delete the stale record, and create a brand new sandbox.
	req2 := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body = %s", rr2.Code, rr2.Body.String())
	}

	if runtime.createHits != 2 {
		t.Fatalf("expected 2 runtime create hits, got %d", runtime.createHits)
	}
}

func TestE2BResolveTemplateEdgeCases(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newE2BHandlerTestEnv(t)

	err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name:            "test-template:default",
		SourceSandboxID: "sb-1",
		CreatedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to create snapshot: %v", err)
	}

	err = st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{
		Alias:        "snap-alias",
		SnapshotName: "test-template:default",
		Facade:       models.FacadeE2B,
	})
	if err != nil {
		t.Fatalf("failed to create alias: %v", err)
	}

	h := newHandlers(Deps{Service: svc})

	img, alias, err := h.resolveTemplate(ctx, "snap-alias")
	if err != nil || img != "test-template:default" {
		t.Fatalf("resolveTemplate(alias) = %q, %q, %v", img, alias, err)
	}

	encodedID := snapshotIDFromName("test-template:default")
	img, alias, err = h.resolveTemplate(ctx, encodedID)
	if err != nil || img != "test-template:default" {
		t.Fatalf("resolveTemplate(encoded) = %q, %q, %v", img, alias, err)
	}

	img, alias, err = h.resolveTemplate(ctx, "base")
	if err != nil || img != "ubuntu:22.04" {
		t.Fatalf("resolveTemplate(base) = %q, %q, %v", img, alias, err)
	}

	_, _, err = h.resolveTemplate(ctx, "nonexistent-template")
	if err == nil {
		t.Fatal("expected error resolving nonexistent template")
	}
}

func TestE2BResolveSnapshotDeleteTargetEdgeCases(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newE2BHandlerTestEnv(t)

	err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name:            "snap-delete:default",
		SourceSandboxID: "sb-1",
		CreatedAt:       time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to create snapshot: %v", err)
	}

	h := newHandlers(Deps{Service: svc})

	encoded := snapshotIDFromName("snap-delete:default")
	name, storedID, err := h.resolveSnapshotDeleteTarget(ctx, encoded)
	if err != nil || name != "snap-delete:default" || storedID != encoded {
		t.Fatalf("resolveSnapshotDeleteTarget(encoded) = %q, %q, %v", name, storedID, err)
	}

	name, storedID, err = h.resolveSnapshotDeleteTarget(ctx, "snap-delete:default")
	if err != nil || name != "snap-delete:default" {
		t.Fatalf("resolveSnapshotDeleteTarget(name) = %q, %q, %v", name, storedID, err)
	}

	// Canonical resolution check
	name, storedID, err = h.resolveSnapshotDeleteTarget(ctx, "snap-delete")
	if err != nil || name != "snap-delete:default" {
		t.Fatalf("resolveSnapshotDeleteTarget(canonical) = %q, %q, %v", name, storedID, err)
	}

	_, _, err = h.resolveSnapshotDeleteTarget(ctx, "nonexistent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestE2BHelperFunctions(t *testing.T) {
	_, err := stringMap(map[string]any{"key": 123}, "metadata")
	if err == nil || !strings.Contains(err.Error(), "must be strings") {
		t.Fatalf("expected stringMap type error, got %v", err)
	}

	loggerOutput := &strings.Builder{}
	logger := slog.New(slog.NewTextHandler(loggerOutput, nil))
	t.Setenv("SB_E2B_TEMPLATE_MAP_JSON", "{invalid-json}")
	templates := loadTemplateMap(logger)
	if templates["base"] != "ubuntu:22.04" {
		t.Fatalf("expected template fallback, got %+v", templates)
	}
	if !strings.Contains(loggerOutput.String(), "invalid SB_E2B_TEMPLATE_MAP_JSON") {
		t.Fatalf("expected log output to warn about JSON, got %q", loggerOutput.String())
	}

	parsed, err := parseMetadataFilter("  ")
	if err != nil || parsed != nil {
		t.Fatalf("parseMetadataFilter(blank) = %+v, %v", parsed, err)
	}
	parsedVal, err := parseMetadataFilter("key")
	if err != nil || parsedVal["key"] != "" {
		t.Fatalf("parseMetadataFilter(key) = %+v, %v", parsedVal, err)
	}

	sb := &models.Sandbox{ToolboxToken: "my-token"}
	tokSec := envdAccessToken(sb, sandboxMeta{Secure: true})
	if tokSec != "my-token" {
		t.Fatalf("expected token, got %q", tokSec)
	}
	tokInsec := envdAccessToken(sb, sandboxMeta{Secure: false})
	if tokInsec != "" {
		t.Fatalf("expected empty token for insecure, got %q", tokInsec)
	}

	if count := sandboxCPUCount(nil); count != 1 {
		t.Fatalf("sandboxCPUCount(nil) = %d, want 1", count)
	}
	if count := sandboxCPUCount(&models.Sandbox{CPU: -1.0}); count != 1 {
		t.Fatalf("sandboxCPUCount(-1.0) = %d, want 1", count)
	}

	if got := startedAt(nil); got.IsZero() {
		t.Fatal("startedAt(nil) should not be zero")
	}
	if got := startedAt(&models.Sandbox{}); got.IsZero() {
		t.Fatal("startedAt(empty) should not be zero")
	}

	if id := loadClientID(); id != defaultClientID {
		t.Fatalf("expected default client ID, got %q", id)
	}

	if val := firstNonEmpty("", "  "); val != "" {
		t.Fatalf("expected empty, got %q", val)
	}

	if state := mapSandboxState(models.SandboxStatusStopped); state != "paused" {
		t.Fatalf("mapSandboxState(Stopped) = %q, want paused", state)
	}
	if contains := metadataContains(map[string]string{"a": "1"}, map[string]string{"a": "2"}); contains {
		t.Fatal("metadataContains should report mismatch")
	}

	items := []listedSandboxResponse{{SandboxID: "1"}, {SandboxID: "2"}}
	page, tok := paginateListedSandboxes(items, 5, 2)
	if len(page) != 0 || tok != "" {
		t.Fatalf("paginateListedSandboxes bounds = %+v, %q", page, tok)
	}

	pageSnap, tokSnap := paginateSnapshots([]snapshotInfoResponse{{SnapshotID: "1"}}, 5, 2)
	if len(pageSnap) != 0 || tokSnap != "" {
		t.Fatalf("paginateSnapshots bounds = %+v, %q", pageSnap, tokSnap)
	}
}

func TestE2BListSandboxesCompatStateError(t *testing.T) {
	ctx := context.Background()
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	if err := st.UpsertCompatState(ctx, id, models.FacadeE2B, "{bad"); err != nil {
		t.Fatalf("failed to upsert compat state: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 bad request, got %d", rr.Code)
	}
}

func TestE2BGetSandboxCompatStateError(t *testing.T) {
	ctx := context.Background()
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	if err := st.UpsertCompatState(ctx, id, models.FacadeE2B, "{bad"); err != nil {
		t.Fatalf("failed to upsert: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes/"+id, nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestE2BConnectSandboxCompatStateError(t *testing.T) {
	ctx := context.Background()
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	if err := st.UpsertCompatState(ctx, id, models.FacadeE2B, "{bad"); err != nil {
		t.Fatalf("failed to upsert: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/connect", strings.NewReader(`{"timeout":90}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestE2BUpdateTimeoutCompatStateError(t *testing.T) {
	ctx := context.Background()
	_, st, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	if err := st.UpsertCompatState(ctx, id, models.FacadeE2B, "{bad"); err != nil {
		t.Fatalf("failed to upsert: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/timeout", strings.NewReader(`{"timeout":90}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestE2BCreateSandboxBlockAllEgress(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","network":{"denyOut":["0.0.0.0/0"]}}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body = %s", rr.Code, rr.Body.String())
	}
}

func TestE2BResolveTemplateMoreEdgeCases(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})

	_, _, err := h.resolveTemplate(ctx, snapshotIDFromName("nonexistent"))
	if err == nil {
		t.Fatal("expected error resolving decoded nonexistent template")
	}
}

func TestWaitForCreateReplayContextCanceled(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, replayed, err := h.waitForCreateReplay(ctx, "fp")
	if err == nil || replayed {
		t.Fatalf("expected cancel error, got replayed=%v err=%v", replayed, err)
	}
}

func TestLifecyclePayloadEmpty(t *testing.T) {
	payload := lifecyclePayload(sandboxMeta{})
	if payload != nil {
		t.Fatalf("expected nil payload, got %+v", payload)
	}
}

func TestNetworkPayloadEmpty(t *testing.T) {
	payload := networkPayload(sandboxMeta{})
	if payload != nil {
		t.Fatalf("expected nil payload, got %+v", payload)
	}
}

func TestTimeoutDeadlineFallback(t *testing.T) {
	base := time.Now()
	sb := &models.Sandbox{CreatedAt: base, Lifecycle: models.Lifecycle{StopAtAge: time.Hour}}
	d, ok := timeoutDeadline(sb, sandboxMeta{OnTimeout: "other"})
	if !ok || !d.Equal(base.Add(time.Hour)) {
		t.Fatalf("expected fallback deadline, got %v, %v", d, ok)
	}
	sb2 := &models.Sandbox{CreatedAt: base, Lifecycle: models.Lifecycle{DestroyAtAge: time.Hour}}
	d2, ok2 := timeoutDeadline(sb2, sandboxMeta{OnTimeout: "other"})
	if !ok2 || !d2.Equal(base.Add(time.Hour)) {
		t.Fatalf("expected fallback deadline, got %v, %v", d2, ok2)
	}
}

func TestLifecycleForTimeoutWithElapsed(t *testing.T) {
	base := time.Now().Add(-5 * time.Minute)
	sb := &models.Sandbox{CreatedAt: base}
	lifecycle := lifecycleForTimeout(sb, "pause", 120)
	if lifecycle.StopAtAge <= 120*time.Second {
		t.Fatalf("expected StopAtAge to include elapsed time, got %v", lifecycle.StopAtAge)
	}
}

func TestE2BConnectSandboxExtendsTimeout(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	// Current timeout is 120 (from createE2BSandbox). Extend to 200.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/connect", strings.NewReader(`{"timeout":200}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d; body = %s", rr.Code, rr.Body.String())
	}

	// Verify new timeout in details
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes/"+id, nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("get sandbox failed: %d", rr2.Code)
	}
	var detail sandboxDetailResponse
	if err := json.NewDecoder(rr2.Body).Decode(&detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if detail.EndAt == "" {
		t.Fatal("expected non-empty EndAt")
	}
}

func TestE2BCreateServerlessDestroyAtAge(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	body := `{"templateID":"base","timeout":120,"metadata":{"aerolvm.serverless":"true"}}`
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body = %s", rr.Code, rr.Body.String())
	}
}

func TestNetworkPayloadNonNil(t *testing.T) {
	deny := []string{"0.0.0.0/0"}
	payload := networkPayload(sandboxMeta{NetworkDenyOut: deny})
	if payload == nil || len(payload.DenyOut) != 1 || payload.DenyOut[0] != "0.0.0.0/0" {
		t.Fatalf("expected payload, got %+v", payload)
	}
}

func TestE2BListSandboxesFilteringAndSorting(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)

	// Create Sandbox A (timeout=120)
	idA := createE2BSandbox(t, handler)
	// Create Sandbox B (timeout=121)
	reqB := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","timeout":121}`))
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	if rrB.Code != http.StatusCreated {
		t.Fatalf("create Sandbox B got status = %d", rrB.Code)
	}
	var respB sandboxResponse
	_ = json.NewDecoder(rrB.Body).Decode(&respB)
	idB := respB.SandboxID

	// 1. Filter by state "paused" (both are started/running, so returns empty)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?state=paused", nil))
	if rr1.Code != http.StatusOK {
		t.Fatalf("list state=paused: status = %d", rr1.Code)
	}
	var list1 []listedSandboxResponse
	_ = json.NewDecoder(rr1.Body).Decode(&list1)
	if len(list1) != 0 {
		t.Fatalf("expected 0 sandboxes, got %d", len(list1))
	}

	// 2. Filter by metadata tag mismatch
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?metadata=team%3Dnonexistent", nil))
	var list2 []listedSandboxResponse
	_ = json.NewDecoder(rr2.Body).Decode(&list2)
	if len(list2) != 0 {
		t.Fatalf("expected 0 matching tags, got %d", len(list2))
	}

	// 3. General list sorting validation
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	var list3 []listedSandboxResponse
	_ = json.NewDecoder(rr3.Body).Decode(&list3)
	if len(list3) < 2 {
		t.Fatalf("expected at least 2 sandboxes, got %d", len(list3))
	}
	// Sorted by startedAt descending, then sandboxID
	first := list3[0].SandboxID
	second := list3[1].SandboxID
	if first == second {
		t.Fatal("expected unique sandbox IDs in list")
	}

	// Clean up one sandbox to test the list loop continue paths
	rrDel := httptest.NewRecorder()
	handler.ServeHTTP(rrDel, httptest.NewRequest(http.MethodDelete, "/e2b/sandboxes/"+idA, nil))
	if rrDel.Code != http.StatusNoContent {
		t.Fatalf("delete sandbox failed: %d", rrDel.Code)
	}

	rr4 := httptest.NewRecorder()
	handler.ServeHTTP(rr4, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	var list4 []listedSandboxResponse
	_ = json.NewDecoder(rr4.Body).Decode(&list4)
	foundA := false
	foundB := false
	for _, item := range list4 {
		if item.SandboxID == idA {
			foundA = true
		}
		if item.SandboxID == idB {
			foundB = true
		}
	}
	if foundA || !foundB {
		t.Fatalf("list status after deletion: foundA=%v foundB=%v", foundA, foundB)
	}
}

func TestE2BListSnapshotsFilteringAndSorting(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	// Create snapshot
	rrSnap := httptest.NewRecorder()
	handler.ServeHTTP(rrSnap, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"snap-list-1"}`)))
	if rrSnap.Code != http.StatusCreated {
		t.Fatalf("snapshot status = %d", rrSnap.Code)
	}

	// Filter by nonexistent sandboxID
	rrList := httptest.NewRecorder()
	handler.ServeHTTP(rrList, httptest.NewRequest(http.MethodGet, "/e2b/snapshots?sandboxID=nonexistent", nil))
	var snaps []snapshotInfoResponse
	_ = json.NewDecoder(rrList.Body).Decode(&snaps)
	if len(snaps) != 0 {
		t.Fatalf("expected 0 snapshots for nonexistent sandbox, got %d", len(snaps))
	}
}

func TestLoadSandboxMetaNil(t *testing.T) {
	svc, _, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	meta, err := h.loadSandboxMeta(context.Background(), nil)
	if err != nil || !meta.Secure {
		t.Fatalf("expected default secure meta, got %+v, %v", meta, err)
	}
}

func TestPersistSandboxMetaNilService(t *testing.T) {
	h := newHandlers(Deps{})
	err := h.persistSandboxMeta(context.Background(), "sb-1", sandboxMeta{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestLoadReplayableCreateResultEdgeCases(t *testing.T) {
	h := newHandlers(Deps{})
	sb, meta, replayed, err := h.loadReplayableCreateResult(context.Background(), nil)
	if err != nil || sb != nil || replayed {
		t.Fatalf("expected nil, got %+v, %+v, %v, %v", sb, meta, replayed, err)
	}
	sb, meta, replayed, err = h.loadReplayableCreateResult(context.Background(), &models.IdempotentRequestRecord{TargetID: " "})
	if err != nil || sb != nil || replayed {
		t.Fatalf("expected nil for empty target, got %+v, %+v, %v, %v", sb, meta, replayed, err)
	}
}

func TestE2BDeleteSnapshotEmptyID(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/e2b/templates/%20", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestLoadClientIDEnv(t *testing.T) {
	t.Setenv("SB_E2B_CLIENT_ID", "custom-client-id")
	id := loadClientID()
	if id != "custom-client-id" {
		t.Fatalf("expected custom-client-id, got %q", id)
	}
}

func TestE2BCreateSandboxStringMapErrors(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)

	// Invalid metadata value type (integer)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","metadata":{"key":123}}`)))
	if rr1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr1.Code)
	}

	// Invalid envVars value type (boolean)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","envVars":{"key":true}}`)))
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr2.Code)
	}
}

func TestE2BListSandboxesSortingEqualStartedAt(t *testing.T) {
	ctx := context.Background()
	_, st, handler := newE2BHandlerTestEnv(t)

	id1 := createE2BSandbox(t, handler)

	req2 := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","timeout":121}`))
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	var created2 sandboxResponse
	_ = json.NewDecoder(rr2.Body).Decode(&created2)
	id2 := created2.SandboxID

	now := time.Unix(1000, 0).UTC()
	sb1, _ := st.Get(ctx, id1)
	sb1.CreatedAt = now
	_ = st.Delete(ctx, id1)
	_ = st.Create(ctx, sb1)

	sb2, _ := st.Get(ctx, id2)
	sb2.CreatedAt = now
	_ = st.Delete(ctx, id2)
	_ = st.Create(ctx, sb2)

	rrList := httptest.NewRecorder()
	handler.ServeHTTP(rrList, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes", nil))
	var list []listedSandboxResponse
	_ = json.NewDecoder(rrList.Body).Decode(&list)

	if len(list) < 2 {
		t.Fatalf("expected 2 sandboxes, got %d", len(list))
	}
	expectedFirst := id1
	expectedSecond := id2
	if id2 < id1 {
		expectedFirst = id2
		expectedSecond = id1
	}
	if list[0].SandboxID != expectedFirst || list[1].SandboxID != expectedSecond {
		t.Fatalf("sorting mismatch: got [%s, %s], expected [%s, %s]", list[0].SandboxID, list[1].SandboxID, expectedFirst, expectedSecond)
	}
}

func TestE2BUpdateTimeoutValidation(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	// Bad JSON
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/timeout", strings.NewReader(`{bad`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	// Timeout <= 0
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/timeout", strings.NewReader(`{"timeout":0}`)))
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr2.Code)
	}
}

func TestE2BCreateSnapshotBadJSON(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{bad`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestE2BCreateSnapshotRuntimeFails(t *testing.T) {
	runtime := newFakeE2BRuntime()
	runtime.errCreateSnapshot = errors.New("injected snapshot creation error")
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: 2280})

	id := createE2BSandbox(t, handler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"snap-fail"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body = %s", rr.Code, rr.Body.String())
	}
}

func TestE2BListSandboxesPaginationNextToken(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	_ = createE2BSandbox(t, handler)
	reqB := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","timeout":121}`))
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	if rrB.Code != http.StatusCreated {
		t.Fatalf("failed to create B: %d", rrB.Code)
	}

	rrList := httptest.NewRecorder()
	handler.ServeHTTP(rrList, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?limit=1", nil))
	if rrList.Code != http.StatusOK {
		t.Fatalf("list failed: %d", rrList.Code)
	}
	tok := rrList.Header().Get("x-next-token")
	if tok == "" {
		t.Fatal("expected x-next-token header")
	}

	rrList2 := httptest.NewRecorder()
	handler.ServeHTTP(rrList2, httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?limit=1&nextToken="+tok, nil))
	if rrList2.Code != http.StatusOK {
		t.Fatalf("list page 2 failed: %d", rrList2.Code)
	}
}

func TestE2BListSnapshotsPaginationNextToken(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	rrSnap1 := httptest.NewRecorder()
	handler.ServeHTTP(rrSnap1, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"snap-1"}`)))
	if rrSnap1.Code != http.StatusCreated {
		t.Fatalf("snapshot 1: %d", rrSnap1.Code)
	}

	rrSnap2 := httptest.NewRecorder()
	handler.ServeHTTP(rrSnap2, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots", strings.NewReader(`{"name":"snap-2"}`)))
	if rrSnap2.Code != http.StatusCreated {
		t.Fatalf("snapshot 2: %d", rrSnap2.Code)
	}

	rrList := httptest.NewRecorder()
	handler.ServeHTTP(rrList, httptest.NewRequest(http.MethodGet, "/e2b/snapshots?limit=1", nil))
	if rrList.Code != http.StatusOK {
		t.Fatalf("list snaps: %d", rrList.Code)
	}
	tok := rrList.Header().Get("x-next-token")
	if tok == "" {
		t.Fatal("expected x-next-token for snapshots")
	}
}

func TestLoadTemplateMapEmpty(t *testing.T) {
	t.Setenv("SB_E2B_TEMPLATE_MAP_JSON", "")
	templates := loadTemplateMap(nil)
	if templates["base"] != "ubuntu:22.04" {
		t.Fatalf("expected default, got %+v", templates)
	}
}

func TestLoadTemplateMapWithoutBase(t *testing.T) {
	t.Setenv("SB_E2B_TEMPLATE_MAP_JSON", `{"custom":"image"}`)
	templates := loadTemplateMap(nil)
	if templates["base"] != "ubuntu:22.04" || templates["custom"] != "image" {
		t.Fatalf("expected base default and custom, got %+v", templates)
	}
}
