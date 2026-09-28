package daytona

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
