package service

import (
	"bufio"
	"context"
	"errors"
	"expvar"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func toolboxCallCount(surface, route, class string) int64 {
	routes, ok := toolboxCallsTotal.Get(surface).(*expvar.Map)
	if !ok {
		return 0
	}
	classes, ok := routes.Get(route).(*expvar.Map)
	if !ok {
		return 0
	}
	n, ok := classes.Get(class).(*expvar.Int)
	if !ok {
		return 0
	}
	return n.Value()
}

func TestToolboxRouteClass(t *testing.T) {
	for path, want := range map[string]string{
		"/files":                               "files",
		"/files/info":                          "files",
		"/files/watch":                         "watch",
		"/envd/files":                          "files",
		"/envd/filesystem.Filesystem/Stat":     "files",
		"/envd/filesystem.Filesystem/WatchDir": "watch",
		"/envd/filesystem.Filesystem/CreateWatcher":    "watch",
		"/envd/filesystem.Filesystem/GetWatcherEvents": "watch",
		"/envd/filesystem.Filesystem/RemoveWatcher":    "watch",
		"/process/execute":                             "exec",
		"/process/code-run":                            "exec",
		"/process/exec/stream":                         "exec_stream",
		"/envd/process.Process/Start":                  "exec_stream",
		"/sessions":                                    "sessions",
		"/sessions/s1/attach":                          "sessions",
		"/process/session":                             "sessions",
		"/process/session/s1/exec":                     "sessions",
		"/process/pty":                                 "pty",
		"/process/pty/s1/connect":                      "pty",
		"/lsp/start":                                   "lsp",
		"/git/status":                                  "other",
		"/":                                            "other",
	} {
		if got := toolboxRouteClass(path); got != want {
			t.Errorf("toolboxRouteClass(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestToolboxStatusClass(t *testing.T) {
	for status, want := range map[int]string{
		101: "2xx", 200: "2xx", 204: "2xx", 301: "other", 400: "4xx", 404: "4xx", 409: "4xx", 499: "4xx",
		500: "5xx", 501: "501", 502: "5xx", 507: "5xx", 0: "other",
	} {
		if got := toolboxStatusClass(status); got != want {
			t.Errorf("toolboxStatusClass(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestToolboxErrorStatus(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{ErrSandboxStoppedMidRequest, http.StatusConflict},
		{fmt.Errorf("wrap: %w", store.ErrNotFound), http.StatusNotFound},
		{context.Canceled, 499},
		{errors.New("dial tcp: refused"), http.StatusBadGateway},
	} {
		if got := toolboxErrorStatus(tc.err); got != tc.want {
			t.Errorf("toolboxErrorStatus(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

func TestRecordToolboxCallBySurfaceRouteAndClass(t *testing.T) {
	before := toolboxCallCount("daytona", "lsp", "501")
	ctx := WithToolboxSurface(context.Background(), ToolboxSurfaceDaytona)
	RecordToolboxCall(ctx, "/lsp/start", http.StatusNotImplemented)
	RecordToolboxCall(ctx, "/lsp/stop", http.StatusNotImplemented)
	if got := toolboxCallCount("daytona", "lsp", "501"); got != before+2 {
		t.Fatalf("count = %d, want %d", got, before+2)
	}
	otherBefore := toolboxCallCount("other", "files", "2xx")
	RecordToolboxCall(context.Background(), "/files", http.StatusOK)
	if got := toolboxCallCount("other", "files", "2xx"); got != otherBefore+1 {
		t.Fatalf("unmarked surface not counted as other")
	}
}

type hijackableWriter struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (h *hijackableWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return a, bufio.NewReadWriter(bufio.NewReader(a), bufio.NewWriter(a)), nil
}

func (h *hijackableWriter) Flush() { h.flushed = true }

func TestToolboxStatusRecorder(t *testing.T) {
	rec := NewToolboxStatusRecorder(httptest.NewRecorder())
	_, _ = rec.Write([]byte("x"))
	rec.WriteHeader(http.StatusTeapot)
	if rec.Status() != http.StatusOK {
		t.Fatalf("status after implicit write = %d, want 200", rec.Status())
	}

	rec = NewToolboxStatusRecorder(httptest.NewRecorder())
	rec.WriteHeader(http.StatusNotImplemented)
	if rec.Status() != http.StatusNotImplemented {
		t.Fatalf("status = %d", rec.Status())
	}

	inner := &hijackableWriter{ResponseRecorder: httptest.NewRecorder()}
	rec = NewToolboxStatusRecorder(inner)
	rec.Flush()
	if !inner.flushed {
		t.Fatal("Flush not passed through")
	}
	conn, _, err := rec.Hijack()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if rec.Status() != http.StatusSwitchingProtocols {
		t.Fatalf("hijack status = %d, want 101", rec.Status())
	}
	if rec.Unwrap() != http.ResponseWriter(inner) {
		t.Fatal("Unwrap did not return the inner writer")
	}

	plain := NewToolboxStatusRecorder(httptest.NewRecorder())
	if _, _, err := plain.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Hijack on a non-hijacker = %v", err)
	}
	plain.Flush() // no Flusher: must not panic
}

// O4 at the two service proxy points: the reverse proxy (v1, Daytona) and
// RoundTripToolbox (Daytona forwards, Runloop), including a call that fails
// before any response.
func TestToolboxProxiesCountCalls(t *testing.T) {
	ctx := context.Background()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/lsp/") {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	var port int
	fmt.Sscanf(strings.Split(ts.URL, ":")[2], "%d", &port)
	svc.cfg.ToolboxPort = port
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-o4", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted,
		ToolboxToken: "tok", ContainerIP: "127.0.0.1", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	v1Before := toolboxCallCount("v1", "lsp", "501")
	req := httptest.NewRequest(http.MethodPost, "http://x/lsp/start", nil)
	if err := svc.ServeToolboxReverseProxy(WithToolboxSurface(ctx, ToolboxSurfaceV1), "sb-o4", httptest.NewRecorder(), req, "/lsp/start"); err != nil {
		t.Fatal(err)
	}
	if got := toolboxCallCount("v1", "lsp", "501"); got != v1Before+1 {
		t.Fatalf("reverse proxy not counted: %d", got)
	}

	rlBefore := toolboxCallCount("runloop", "files", "2xx")
	resp, err := svc.RoundTripToolbox(WithToolboxSurface(ctx, ToolboxSurfaceRunloop), "sb-o4", http.MethodGet, "/files/download", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := toolboxCallCount("runloop", "files", "2xx"); got != rlBefore+1 {
		t.Fatalf("round trip not counted: %d", got)
	}

	missBefore := toolboxCallCount("daytona", "exec", "4xx")
	if _, err := svc.RoundTripToolbox(WithToolboxSurface(ctx, ToolboxSurfaceDaytona), "sb-missing", http.MethodPost, "/process/execute", nil, nil, nil); err == nil {
		t.Fatal("round trip to a missing sandbox succeeded")
	}
	if got := toolboxCallCount("daytona", "exec", "4xx"); got != missBefore+1 {
		t.Fatalf("failed round trip not counted as 4xx: %d", got)
	}
}
