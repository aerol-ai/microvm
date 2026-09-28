package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeIsolateToolboxHost struct {
	*recordingRuntime
	served int
}

func (f *fakeIsolateToolboxHost) ServeToolbox(_ context.Context, _ string, _ string, w http.ResponseWriter, _ *http.Request) {
	f.served++
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("isolate-toolbox"))
}

func TestServeToolboxReverseProxyIsolateAndSSHForwardLog(t *testing.T) {
	ctx := context.Background()
	host := &fakeIsolateToolboxHost{recordingRuntime: &recordingRuntime{}}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.SetIsolateRuntime(host)
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-iso-tb", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted,
		ToolboxToken: "tok", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/files", nil)
	req.Header.Set("X-Aerol-Ssh-Forward-Id", "fwd-1")
	rec := httptest.NewRecorder()
	if err := svc.ServeToolboxReverseProxy(ctx, "sb-iso-tb", rec, req, "/files"); err != nil {
		t.Fatalf("ServeToolboxReverseProxy: %v", err)
	}
	if rec.Body.String() != "isolate-toolbox" || host.served != 1 {
		t.Fatalf("body=%q served=%d", rec.Body.String(), host.served)
	}

	svc.SetIsolateRuntime(&recordingRuntime{})
	if err := svc.ServeToolboxReverseProxy(ctx, "sb-iso-tb", httptest.NewRecorder(), req, "/x"); err == nil || !strings.Contains(err.Error(), "toolbox host") {
		t.Fatalf("err = %v", err)
	}
	svc.isolate = nil
	if err := svc.ServeToolboxReverseProxy(ctx, "sb-iso-tb", httptest.NewRecorder(), req, "/x"); err == nil || !strings.Contains(err.Error(), "driver not registered") {
		t.Fatalf("err = %v", err)
	}
}
