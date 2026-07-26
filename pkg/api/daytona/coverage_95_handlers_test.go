package daytona

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSetAutoArchiveAndIdleLifecycleErrors(t *testing.T) {
	handler, svc, _ := newDaytonaVolumesTestEnv(t)
	ctx := context.Background()
	sb, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}

	// Invalid interval path param.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/"+sb.ID+"/autoarchive/not-a-number", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected bad interval rejection")
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/daytona/sandbox/"+sb.ID+"/autostop/not-a-number", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected autostop bad interval rejection")
	}

	// Missing sandbox.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/daytona/sandbox/missing-id/autoarchive/5", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected missing sandbox error")
	}
}

func TestDestroyStartStopPreviewErrorPaths(t *testing.T) {
	handler, _, _ := newDaytonaVolumesTestEnv(t)

	for _, path := range []string{
		"/daytona/sandbox/nope",
		"/daytona/sandbox/nope/start",
		"/daytona/sandbox/nope/stop",
		"/daytona/sandbox/nope/ports/8080/preview-url",
	} {
		rr := httptest.NewRecorder()
		method := http.MethodGet
		if path == "/daytona/sandbox/nope" {
			method = http.MethodDelete
		} else if path != "/daytona/sandbox/nope/ports/8080/preview-url" {
			method = http.MethodPost
		}
		handler.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
		if rr.Code == http.StatusOK {
			t.Fatalf("%s: expected error status, got %d", path, rr.Code)
		}
	}
}

func TestReplaceLabelsBadJSON(t *testing.T) {
	handler, svc, _ := newDaytonaVolumesTestEnv(t)
	sb, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/daytona/sandbox/"+sb.ID+"/labels", bytes.NewReader([]byte(`{bad`)))
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatal("expected bad JSON rejection")
	}

	body, _ := json.Marshal(map[string]string{"env": "dev"})
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/daytona/sandbox/"+sb.ID+"/labels", bytes.NewReader(body))
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("labels status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlerPostSuccessMetaLoadErrorsCoverage95(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-bad-meta-ops", Name: "bad-meta-ops", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-bad", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := st.UpsertCompatState(context.Background(), sb.ID, models.FacadeDaytona, "{bad"); err != nil {
		t.Fatalf("UpsertCompatState: %v", err)
	}
	rt.startState = &models.SandboxRuntimeState{SandboxID: sb.ID, Status: models.SandboxStatusStarted}
	rt.inspectState = rt.startState

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"start", http.MethodPost, "/daytona/sandbox/bad-meta-ops/start", ""},
		{"stop", http.MethodPost, "/daytona/sandbox/bad-meta-ops/stop", ""},
		{"resize", http.MethodPost, "/daytona/sandbox/bad-meta-ops/resize", `{"cpu":2}`},
		{"snapshot", http.MethodPost, "/daytona/sandbox/bad-meta-ops/snapshot", `{"name":"snap"}`},
		{"autoarchive", http.MethodPost, "/daytona/sandbox/bad-meta-ops/autoarchive/5", ""},
		{"autostop", http.MethodPost, "/daytona/sandbox/bad-meta-ops/autostop/5", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.SetPathValue("idOrName", "bad-meta-ops")
			if tc.name == "autoarchive" || tc.name == "autostop" {
				req.SetPathValue("interval", "5")
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code == http.StatusOK {
				t.Fatalf("expected meta load failure, got %d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestDestroySandboxDestroyErrorCoverage95(t *testing.T) {
	_, st, rt, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-destroy-err", Name: "destroy-err", Status: models.SandboxStatusStarted,
		ContainerID: "ctr", ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rt.destroyErr = errors.New("destroy failed")

	req := httptest.NewRequest(http.MethodDelete, "/daytona/sandbox/destroy-err", nil)
	req.SetPathValue("idOrName", "destroy-err")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("expected destroy error, got %d", rr.Code)
	}
}

func TestListSandboxesPaginatedBeyondTotalCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID: "sb-page", Name: "only-one", Status: models.SandboxStatusStarted,
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?page=99&limit=10", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var page paginatedSandboxesResponse
	if err := json.NewDecoder(rr.Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("expected empty page, got %+v", page.Items)
	}
}

func TestSetAutoArchiveIntervalNegativeCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID: "sb-neg-archive", Name: "neg-archive", Status: models.SandboxStatusStarted,
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/neg-archive/autoarchive/-1", nil)
	req.SetPathValue("idOrName", "neg-archive")
	req.SetPathValue("interval", "-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestPreviewURLExposePortErrorCoverage95(t *testing.T) {
	_, st, _, handler := newHandlerExtraTestEnv(t)
	now := time.Now().UTC()
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID: "sb-preview-err", Name: "preview-err", Status: models.SandboxStatusStarted,
		ToolboxEnabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/preview-err/ports/99999/preview-url", nil)
	req.SetPathValue("idOrName", "preview-err")
	req.SetPathValue("port", "99999")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Fatalf("expected expose error, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestLoadSandboxMetaNilSandboxCoverage95(t *testing.T) {
	svc, _, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc})
	meta, err := h.loadSandboxMeta(context.Background(), nil)
	if err != nil {
		t.Fatalf("loadSandboxMeta(nil): %v", err)
	}
	if meta.Labels == nil {
		t.Fatal("expected initialized labels map")
	}
}

func TestTranslateCreateSandboxRequestRejectionsCoverage95(t *testing.T) {
	h := newHandlers(Deps{})
	netAllow := "github.com"
	_, _, err := h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{
		NetworkAllowList: &netAllow,
	})
	if err == nil || !strings.Contains(err.Error(), "networkAllowList") {
		t.Fatalf("networkAllowList err = %v", err)
	}

	gpu := int32(1)
	_, _, err = h.translateCreateSandboxRequest(context.Background(), createSandboxRequest{Gpu: &gpu})
	if err == nil || !strings.Contains(err.Error(), "gpu") {
		t.Fatalf("gpu err = %v", err)
	}
}

type onLogImageBuilder struct {
	fakeImageBuilder
}

func (b *onLogImageBuilder) BuildImage(ctx context.Context, req docker.BuildImageRequest) error {
	if req.OnLog != nil {
		req.OnLog("layer 1/1")
	}
	return b.fakeImageBuilder.BuildImage(ctx, req)
}

func TestResolveBuildInfoOnLogCoverage95(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := newHandlers(Deps{
		Logger:  logger,
		Builder: &onLogImageBuilder{},
	})
	_, _, err := h.resolveBuildInfo(context.Background(), &buildInfoRequest{
		DockerfileContent: stringPtr("FROM alpine\nRUN echo hi"),
	})
	if err != nil {
		t.Fatalf("resolveBuildInfo: %v", err)
	}
}

func TestForwardToolboxErrorCoverage95(t *testing.T) {
	svc, _, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	req := httptest.NewRequest(http.MethodGet, "/files", nil)
	rr := httptest.NewRecorder()
	h.forwardToolbox(rr, req, "missing-sandbox", "/files")
	if rr.Code == http.StatusOK {
		t.Fatalf("expected error status, got %d", rr.Code)
	}
}
