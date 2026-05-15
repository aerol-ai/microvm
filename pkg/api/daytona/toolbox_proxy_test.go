package daytona

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// fakeToolboxRouteRuntime is the bare-minimum runtime.Runtime needed to seed a
// sandbox into the store for ToolboxTarget(...) to resolve. None of the
// runtime hooks fire during proxy tests; we panic on anything unexpected so a
// surprise call is loud, not silent.
type fakeToolboxRouteRuntime struct{}

func (fakeToolboxRouteRuntime) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	panic("unexpected Create")
}
func (fakeToolboxRouteRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Start")
}
func (fakeToolboxRouteRuntime) Stop(context.Context, string) error { panic("unexpected Stop") }
func (fakeToolboxRouteRuntime) Destroy(context.Context, *models.Sandbox) error {
	panic("unexpected Destroy")
}
func (fakeToolboxRouteRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	panic("unexpected CreateSnapshot")
}
func (fakeToolboxRouteRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	panic("unexpected Resize")
}
func (fakeToolboxRouteRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("unexpected Inspect")
}
func (fakeToolboxRouteRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	return map[string]*models.SandboxRuntimeState{}, nil
}
func (fakeToolboxRouteRuntime) Ping(context.Context) error          { return nil }
func (fakeToolboxRouteRuntime) RemoveImage(context.Context, string) error { return nil }
func (fakeToolboxRouteRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	return nil
}
func (fakeToolboxRouteRuntime) ClearNetworkRules(string) error        { return nil }
func (fakeToolboxRouteRuntime) ApplyNetworkBlockAll(string) error     { return nil }
func (fakeToolboxRouteRuntime) ApplyNetworkBlockIngress(string) error { return nil }
func (fakeToolboxRouteRuntime) ClearNetworkBlockIngress(string) error { return nil }
func (fakeToolboxRouteRuntime) ClearNetworkBlockEgress(string) error  { return nil }

// toolboxProxyTestEnv wires a fake "toolbox daemon" httptest.Server into the
// daytona facade so we can drive real HTTP and WebSocket traffic through the
// proxy code under test. ContainerIP + ToolboxPort point at the fake server
// — any request the facade forwards lands on toolboxRequests.
type toolboxProxyTestEnv struct {
	facade           *httptest.Server
	toolbox          *httptest.Server
	sandboxID        string
	toolboxRequests  chan *http.Request
	toolboxWSPath    chan string
	toolboxWSCloseFn func()
}

func newToolboxProxyTestEnv(t *testing.T) *toolboxProxyTestEnv {
	t.Helper()

	requests := make(chan *http.Request, 8)
	wsPaths := make(chan string, 8)
	wsClose := func() {}

	upgrader := websocket.Upgrader{
		// Tests speak ws://127.0.0.1:NNNN directly — there's no browser
		// origin to validate.
		CheckOrigin: func(*http.Request) bool { return true },
	}

	mux := http.NewServeMux()

	// Plain-HTTP endpoints we expect to ride forwardToolbox.
	mux.HandleFunc("/process/code-run", func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"exitCode":0,"result":"hello\n"}`)
	})
	mux.HandleFunc("/process/interpreter/context", func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"ctx-1"}`)
	})

	// WebSocket endpoints we expect to ride proxyToolbox.
	wsHandler := func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade(%s): %v", r.URL.Path, err)
			return
		}
		defer conn.Close()
		// Echo the path back as a text frame so the test can assert
		// the URL was rewritten correctly through the proxy.
		_ = conn.WriteMessage(websocket.TextMessage, []byte(r.URL.Path+"?"+r.URL.RawQuery))
		wsPaths <- r.URL.Path
		// Block until the client closes so the test controls teardown.
		_, _, _ = conn.ReadMessage()
	}
	mux.HandleFunc("/process/interpreter/execute", wsHandler)
	mux.HandleFunc("/process/session/", wsHandler)

	toolboxServer := httptest.NewServer(mux)
	wsClose = toolboxServer.Close

	host, portText, err := net.SplitHostPort(mustParseURL(t, toolboxServer.URL).Host)
	if err != nil {
		t.Fatalf("split toolbox host: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse toolbox port: %v", err)
	}

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mountManager, err := mounts.New(logger, mounts.Config{
		RootDir:     filepath.Join(dir, "mounts"),
		CredDir:     filepath.Join(dir, "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mountManager.Close)

	cfg := config.Config{
		DBPath:            filepath.Join(dir, "state.db"),
		PublicHost:        "sandbox.test",
		ToolboxPort:       port,
		Runtime:           models.RuntimeDocker,
		EnableCaddy:       false,
		HTTPClientTimeout: 5 * time.Second,
	}
	svc := service.New(cfg, logger, st, fakeToolboxRouteRuntime{}, nil, nil, nil, mountManager, nil)

	sandboxID := "sb-proxy"
	now := time.Now().UTC().Round(time.Second)
	if err := st.Upsert(context.Background(), &models.Sandbox{
		ID:             sandboxID,
		Name:           sandboxID,
		Image:          "ubuntu:22.04",
		Status:         models.SandboxStatusStarted,
		ContainerID:    "ctr-" + sandboxID,
		ContainerIP:    host,
		ToolboxEnabled: true,
		ToolboxToken:   "tok-proxy",
		Runtime:        models.RuntimeDocker,
		CreatedAt:      now,
		UpdatedAt:      now,
		LastActiveAt:   now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	mux2 := http.NewServeMux()
	RegisterRoutes(mux2, Deps{
		Service: svc,
		Logger:  logger,
		Auth: func(next http.Handler) http.Handler {
			return next
		},
	})
	facadeServer := httptest.NewServer(mux2)
	t.Cleanup(facadeServer.Close)

	return &toolboxProxyTestEnv{
		facade:           facadeServer,
		toolbox:          toolboxServer,
		sandboxID:        sandboxID,
		toolboxRequests:  requests,
		toolboxWSPath:    wsPaths,
		toolboxWSCloseFn: wsClose,
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// TestToolboxProxyCodeRunForwarded covers the immediate user-reported failure:
// sandbox.process.codeRun() used to 501 because /process/code-run wasn't
// whitelisted in the facade switch.
func TestToolboxProxyCodeRunForwarded(t *testing.T) {
	env := newToolboxProxyTestEnv(t)

	resp, err := http.Post(
		env.facade.URL+ToolboxPrefix+"/"+env.sandboxID+"/process/code-run",
		"application/json",
		strings.NewReader(`{"code":"print(1)","language":"python"}`),
	)
	if err != nil {
		t.Fatalf("POST /process/code-run: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	select {
	case got := <-env.toolboxRequests:
		if got.URL.Path != "/process/code-run" {
			t.Fatalf("forwarded path = %q, want /process/code-run", got.URL.Path)
		}
		if got.Header.Get("Authorization") != "Bearer tok-proxy" {
			t.Fatalf("Authorization = %q, want Bearer tok-proxy", got.Header.Get("Authorization"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("code-run never reached the fake toolbox")
	}
}

// TestToolboxProxyInterpreterContextForwarded confirms the new
// process/interpreter/* prefix routes plain HTTP through proxyToolbox without
// regression. The matching WebSocket path is covered separately below.
func TestToolboxProxyInterpreterContextForwarded(t *testing.T) {
	env := newToolboxProxyTestEnv(t)

	resp, err := http.Post(
		env.facade.URL+ToolboxPrefix+"/"+env.sandboxID+"/process/interpreter/context",
		"application/json",
		strings.NewReader(`{"cwd":"/tmp"}`),
	)
	if err != nil {
		t.Fatalf("POST /process/interpreter/context: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	select {
	case got := <-env.toolboxRequests:
		if got.URL.Path != "/process/interpreter/context" {
			t.Fatalf("forwarded path = %q, want /process/interpreter/context", got.URL.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("interpreter/context never reached the fake toolbox")
	}
}

// TestToolboxProxyInterpreterExecuteUpgradesWebSocket is the regression test
// for the deeper bug: the old forwardToolbox path used httpClient.Do, which
// silently strips the Connection/Upgrade headers and so quietly broke the
// CodeInterpreter stream. proxyToolbox uses httputil.ReverseProxy, which
// passes the upgrade through.
func TestToolboxProxyInterpreterExecuteUpgradesWebSocket(t *testing.T) {
	env := newToolboxProxyTestEnv(t)

	wsURL := strings.Replace(env.facade.URL, "http://", "ws://", 1) +
		ToolboxPrefix + "/" + env.sandboxID + "/process/interpreter/execute"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if msgType != websocket.TextMessage {
		t.Fatalf("frame type = %d, want %d", msgType, websocket.TextMessage)
	}
	if !strings.HasPrefix(string(payload), "/process/interpreter/execute") {
		t.Fatalf("echo payload = %q, want prefix /process/interpreter/execute", payload)
	}

	select {
	case got := <-env.toolboxWSPath:
		if got != "/process/interpreter/execute" {
			t.Fatalf("ws path = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("interpreter/execute upgrade never landed on the fake toolbox")
	}
}

// TestToolboxProxySessionLogsUpgradesWebSocket guards the second WS path the
// example exercises: getSessionCommandLogs(..., onStdout, onStderr) streams
// over /process/session/{id}/command/{cmdId}/logs?follow=true.
func TestToolboxProxySessionLogsUpgradesWebSocket(t *testing.T) {
	env := newToolboxProxyTestEnv(t)

	wsURL := strings.Replace(env.facade.URL, "http://", "ws://", 1) +
		ToolboxPrefix + "/" + env.sandboxID +
		"/process/session/sess-1/command/cmd-1/logs?follow=true"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	want := "/process/session/sess-1/command/cmd-1/logs?follow=true"
	if string(payload) != want {
		t.Fatalf("echoed url = %q, want %q", payload, want)
	}

	select {
	case got := <-env.toolboxWSPath:
		if got != "/process/session/sess-1/command/cmd-1/logs" {
			t.Fatalf("ws path = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session/logs upgrade never landed on the fake toolbox")
	}
}

// TestToolboxProxyUnknownRouteStillReturns501 keeps the default-case
// behavior pinned: only the routes we explicitly whitelist should be
// proxied, so an unmapped path doesn't silently leak into the toolbox.
func TestToolboxProxyUnknownRouteStillReturns501(t *testing.T) {
	env := newToolboxProxyTestEnv(t)

	resp, err := http.Post(
		env.facade.URL+ToolboxPrefix+"/"+env.sandboxID+"/process/not-a-real-route",
		"application/json",
		strings.NewReader(`{}`),
	)
	if err != nil {
		t.Fatalf("POST unknown: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
	select {
	case got := <-env.toolboxRequests:
		t.Fatalf("unknown path leaked to toolbox: %s %s", got.Method, got.URL.Path)
	case <-time.After(100 * time.Millisecond):
		// expected: nothing reaches the toolbox
	}
}

// TestNormalizeToolboxPathInterpreter ensures the path normalizer accepts
// nested interpreter URLs cleanly — defensive coverage so a future refactor
// of normalizeToolboxPath doesn't accidentally swallow part of the URL.
func TestNormalizeToolboxPathInterpreter(t *testing.T) {
	cases := map[string]string{
		"process/interpreter/execute":                 "process/interpreter/execute",
		"process/interpreter/context":                 "process/interpreter/context",
		"process/interpreter/context/abc":             "process/interpreter/context/abc",
		"toolbox/process/interpreter/execute":         "process/interpreter/execute",
		"/toolbox/process/session/s1/command/c1/logs": "process/session/s1/command/c1/logs",
	}
	for input, want := range cases {
		if got := normalizeToolboxPath(input); got != want {
			t.Errorf("normalizeToolboxPath(%q) = %q, want %q", input, got, want)
		}
	}
}

