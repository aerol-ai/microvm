package e2b

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// seenRequest is what the fake toolboxd saw of one forwarded request.
type seenRequest struct {
	method, path, query, auth string
}

type fakeToolbox struct {
	mu   sync.Mutex
	seen []seenRequest
}

func (f *fakeToolbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, seenRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")})
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func (f *fakeToolbox) last(t *testing.T) seenRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) == 0 {
		t.Fatal("nothing reached toolboxd")
	}
	return f.seen[len(f.seen)-1]
}

type interpreterEnv struct {
	svc     *service.Service
	st      *store.Store
	handler http.Handler
	created sandboxResponse
}

// newInterpreterEnv creates a sandbox whose toolboxd is backend, with the
// create body given (secure unless the body says otherwise).
func newInterpreterEnv(t *testing.T, backend http.Handler, createBody string) *interpreterEnv {
	t.Helper()
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)
	host, portText, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	runtime := newFakeE2BRuntime()
	runtime.containerIP = host
	svc, st, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: port})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(createBody)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	env := &interpreterEnv{svc: svc, st: st, handler: handler}
	if err := json.Unmarshal(rec.Body.Bytes(), &env.created); err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *interpreterEnv) runtimeRequest(method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/e2b/runtime"+path, strings.NewReader(`{}`))
	req.Header.Set("E2b-Sandbox-Id", e.created.SandboxID)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func (e *interpreterEnv) setRuntime(t *testing.T, runtime string) {
	t.Helper()
	sb, err := e.svc.GetSandbox(context.Background(), e.created.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	sb.Runtime = runtime
	if err := e.st.Upsert(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeProxyRoutesThePortHeader(t *testing.T) {
	tb := &fakeToolbox{}
	env := newInterpreterEnv(t, tb, `{"templateID":"base"}`)
	token := env.created.EnvdAccessToken
	cases := []struct {
		name, port, method, path, wantPath string
	}{
		{name: "interpreter execute", port: "49999", method: http.MethodPost, path: "/execute", wantPath: "/interpreter/e2b/execute"},
		{name: "interpreter contexts, header padded", port: " 49999 ", method: http.MethodGet, path: "/contexts", wantPath: "/interpreter/e2b/contexts"},
		{name: "interpreter restart", port: "49999", method: http.MethodPost, path: "/contexts/c1/restart", wantPath: "/interpreter/e2b/contexts/c1/restart"},
		{name: "envd port", port: "49983", method: http.MethodPost, path: "/process.Process/Start", wantPath: "/envd/process.Process/Start"},
		{name: "no port header is envd", port: "", method: http.MethodGet, path: "/health", wantPath: "/envd/health"},
		{name: "another port is envd", port: "8080", method: http.MethodGet, path: "/health", wantPath: "/envd/health"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{"X-Access-Token": token}
			if tc.port != "" {
				headers["E2b-Sandbox-Port"] = tc.port
			}
			rec := env.runtimeRequest(tc.method, tc.path+"?ignored=1", headers)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
			}
			got := tb.last(t)
			if got.method != tc.method || got.path != tc.wantPath || got.auth != "Bearer "+token {
				t.Fatalf("toolboxd saw %+v, want %s %s with the toolbox token", got, tc.method, tc.wantPath)
			}
		})
	}
}

// runtimeCall is one request through /e2b/runtime: an interpreter call
// (port 49999) or an envd call.
type runtimeCall struct {
	interpreter  bool
	method, path string
}

var (
	callContexts  = runtimeCall{true, http.MethodGet, "/contexts"}
	callCreate    = runtimeCall{true, http.MethodPost, "/contexts"}
	callDelete    = runtimeCall{true, http.MethodDelete, "/contexts/c1"}
	callRestart   = runtimeCall{true, http.MethodPost, "/contexts/c1/restart"}
	callHealth    = runtimeCall{true, http.MethodGet, "/health"}
	callExecute   = runtimeCall{true, http.MethodPost, "/execute"}
	callEnvd      = runtimeCall{false, http.MethodPost, "/process.Process/Start"}
	callEnvdFiles = runtimeCall{false, http.MethodGet, "/files"}
)

func (e *interpreterEnv) call(c runtimeCall, headers map[string]string) int {
	h := map[string]string{}
	if c.interpreter {
		h["E2b-Sandbox-Port"] = "49999"
	}
	for k, v := range headers {
		h[k] = v
	}
	return e.runtimeRequest(c.method, c.path, h).Code
}

// The traffic token E2B hands out is shareable by E2B's design: it opens a
// sandbox's ports, not envd. It used to be the envd token itself, and was
// accepted on every runtime path, so whoever held it could run commands.
// It is now its own value, and opens only the interpreter's context
// routes and health check; /execute and envd take X-Access-Token.
func TestRuntimeProxyTokenHeaders(t *testing.T) {
	tb := &fakeToolbox{}
	secure := newInterpreterEnv(t, tb, `{"templateID":"base"}`)
	insecure := newInterpreterEnv(t, tb, `{"templateID":"base","secure":false}`)
	envd := secure.created.EnvdAccessToken
	if envd == "" || secure.created.TrafficAccessToken == nil {
		t.Fatalf("a secure sandbox must have both tokens: %+v", secure.created)
	}
	traffic := *secure.created.TrafficAccessToken
	if traffic == envd {
		t.Fatal("the traffic token is the envd token")
	}
	const (
		ok   = http.StatusOK
		deny = http.StatusUnauthorized
	)
	cases := []struct {
		name    string
		env     *interpreterEnv
		headers map[string]string
		want    map[runtimeCall]int
	}{
		{name: "envd token", env: secure, headers: map[string]string{"X-Access-Token": envd},
			want: map[runtimeCall]int{callContexts: ok, callExecute: ok, callEnvd: ok, callEnvdFiles: ok}},
		{name: "traffic token", env: secure, headers: map[string]string{"E2B-Traffic-Access-Token": traffic},
			want: map[runtimeCall]int{
				callContexts: ok, callCreate: ok, callDelete: ok, callRestart: ok, callHealth: ok,
				callExecute: deny, callEnvd: deny, callEnvdFiles: deny,
			}},
		// What the SDKs send on /execute.
		{name: "both tokens", env: secure, headers: map[string]string{"X-Access-Token": envd, "E2B-Traffic-Access-Token": traffic},
			want: map[runtimeCall]int{callExecute: ok, callContexts: ok}},
		{name: "traffic token as the access token", env: secure, headers: map[string]string{"X-Access-Token": traffic},
			want: map[runtimeCall]int{callExecute: deny, callEnvd: deny, callContexts: deny}},
		// Sessions that connected before the change hold the envd token as
		// their traffic token.
		{name: "envd token in the traffic header", env: secure, headers: map[string]string{"E2B-Traffic-Access-Token": envd},
			want: map[runtimeCall]int{callContexts: ok, callExecute: ok, callEnvd: ok}},
		{name: "wrong access token, right traffic token", env: secure, headers: map[string]string{"X-Access-Token": "nope", "E2B-Traffic-Access-Token": traffic},
			want: map[runtimeCall]int{callContexts: ok, callExecute: deny}},
		{name: "both wrong", env: secure, headers: map[string]string{"X-Access-Token": "nope", "E2B-Traffic-Access-Token": "nope"},
			want: map[runtimeCall]int{callContexts: deny, callExecute: deny, callEnvd: deny}},
		{name: "a prefix of a token", env: secure, headers: map[string]string{"E2B-Traffic-Access-Token": traffic[:len(traffic)-1]},
			want: map[runtimeCall]int{callContexts: deny}},
		{name: "none", env: secure, headers: map[string]string{},
			want: map[runtimeCall]int{callContexts: deny, callHealth: deny, callExecute: deny, callEnvd: deny}},
		{name: "insecure sandbox needs none", env: insecure, headers: map[string]string{},
			want: map[runtimeCall]int{callContexts: ok, callExecute: ok, callEnvd: ok}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for c, want := range tc.want {
				if got := tc.env.call(c, tc.headers); got != want {
					t.Errorf("%s %s (interpreter %v) = %d, want %d", c.method, c.path, c.interpreter, got, want)
				}
			}
		})
	}
	// No other spelling of a path takes the traffic token past /execute.
	// The router answers a path that is not clean with a redirect to the
	// clean one, where the check above applies; the others are refused.
	tb.mu.Lock()
	seen := len(tb.seen)
	tb.mu.Unlock()
	for _, p := range []string{"/contexts/../execute", "/contexts/c1/../../execute", "//execute", "/contexts/", "/contexts/c1/restart/x", "/execute/"} {
		if got := secure.call(runtimeCall{true, http.MethodPost, p}, map[string]string{"E2B-Traffic-Access-Token": traffic}); got != deny && got != http.StatusTemporaryRedirect {
			t.Errorf("POST %s with the traffic token = %d, want 401 or a redirect", p, got)
		}
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if len(tb.seen) != seen {
		t.Fatalf("a request reached the sandbox: %+v", tb.seen[seen:])
	}
}

func TestTrafficTokenPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/contexts": true, "/contexts/c1": true, "/contexts/c1/restart": true, "/health": true,
		"/execute": false, "/": false, "/contexts/": false, "/contexts/c1/other": false,
		"/contexts/./c1": false, "/contexts/c1/restart/": false, "/healthz": false, "/contexts//restart": false,
	} {
		if got := trafficTokenPath(p); got != want {
			t.Errorf("trafficTokenPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestRuntimeProxyInterpreterOnIsolate(t *testing.T) {
	tb := &fakeToolbox{}
	env := newInterpreterEnv(t, tb, `{"templateID":"base"}`)
	env.setRuntime(t, models.RuntimeIsolate)
	token := env.created.EnvdAccessToken

	// Auth comes first, so the runtime is not told to a stranger.
	if rec := env.runtimeRequest(http.MethodPost, "/execute", map[string]string{"E2b-Sandbox-Port": "49999"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
	rec := env.runtimeRequest(http.MethodPost, "/execute", map[string]string{"E2b-Sandbox-Port": "49999", "X-Access-Token": token})
	var body errorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusNotImplemented || body.Code != http.StatusNotImplemented ||
		body.Message != "code interpreter is not supported on V8 isolate sandboxes" {
		t.Fatalf("isolate: %d %s", rec.Code, rec.Body.String())
	}
	tb.mu.Lock()
	n := len(tb.seen)
	tb.mu.Unlock()
	if n != 0 {
		t.Fatal("the refused request reached the sandbox")
	}
}

// wasmToolboxHost stands in for the WASM driver's in-process toolbox.
type wasmToolboxHost struct {
	*fakeE2BRuntime
	mu    sync.Mutex
	paths []string
}

func (h *wasmToolboxHost) ServeToolbox(_ context.Context, _, _ string, w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.paths = append(h.paths, r.URL.Path)
	h.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func TestRuntimeProxyInterpreterOnWasmIsForwarded(t *testing.T) {
	env := newInterpreterEnv(t, &fakeToolbox{}, `{"templateID":"base"}`)
	host := &wasmToolboxHost{fakeE2BRuntime: newFakeE2BRuntime()}
	env.svc.SetWasmRuntime(host)
	env.setRuntime(t, models.RuntimeWasm)
	rec := env.runtimeRequest(http.MethodPost, "/execute", map[string]string{"E2b-Sandbox-Port": "49999", "E2B-Traffic-Access-Token": env.created.EnvdAccessToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.paths) != 1 || host.paths[0] != "/interpreter/e2b/execute" {
		t.Fatalf("WASM toolbox saw %q", host.paths)
	}
}

// An /execute stream reaches the SDK line by line, and an SDK that goes
// away ends the toolboxd request, which is what interrupts the run.
func TestRuntimeProxyInterpreterStreamsAndCancels(t *testing.T) {
	release := make(chan struct{})
	ended := make(chan struct{})
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = io.WriteString(w, `{"type":"number_of_executions","execution_count":1}`+"\n")
		_ = http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			close(ended)
		}
	})
	env := newInterpreterEnv(t, backend, `{"templateID":"base"}`)
	front := httptest.NewServer(env.handler)
	t.Cleanup(front.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, front.URL+"/e2b/runtime/execute", strings.NewReader(`{"code":"x"}`))
	req.Header.Set("E2b-Sandbox-Id", env.created.SandboxID)
	req.Header.Set("E2b-Sandbox-Port", "49999")
	req.Header.Set("X-Access-Token", env.created.EnvdAccessToken)
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	lineCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		lineCh <- line
	}()
	select {
	case line := <-lineCh:
		if line != `{"type":"number_of_executions","execution_count":1}`+"\n" {
			t.Fatalf("first line = %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first line was held back by the proxy")
	}
	cancel()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the SDK hung up but toolboxd's request kept going")
	}
}

func TestCreateAndConnectReturnTrafficToken(t *testing.T) {
	svc, _, handler := newE2BHandlerTestEnv(t)
	cases := []struct {
		name      string
		body      string
		wantToken bool
	}{
		{name: "secure", body: `{"templateID":"base"}`, wantToken: true},
		{name: "insecure", body: `{"templateID":"base","secure":false,"metadata":{"k":"insecure"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(tc.body)))
			if rec.Code != http.StatusCreated {
				t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
			}
			var created sandboxResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &created)
			conn := httptest.NewRecorder()
			handler.ServeHTTP(conn, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+created.SandboxID+"/connect", strings.NewReader(`{"timeout":60}`)))
			if conn.Code != http.StatusOK {
				t.Fatalf("connect: %d %s", conn.Code, conn.Body.String())
			}
			sb, err := svc.GetSandbox(context.Background(), created.SandboxID)
			if err != nil || sb.ToolboxToken == "" {
				t.Fatalf("sandbox: %+v %v", sb, err)
			}
			// HMAC-SHA256 keyed by the toolbox token, worked out here on
			// its own so a change to the derivation shows.
			mac := hmac.New(sha256.New, []byte(sb.ToolboxToken))
			mac.Write([]byte("e2b-traffic:" + sb.ID))
			want := hex.EncodeToString(mac.Sum(nil))
			for what, raw := range map[string][]byte{"create": rec.Body.Bytes(), "connect": conn.Body.Bytes()} {
				var got sandboxResponse
				_ = json.Unmarshal(raw, &got)
				switch {
				case tc.wantToken && (got.TrafficAccessToken == nil || *got.TrafficAccessToken != want):
					t.Fatalf("%s: trafficAccessToken = %v, want %q", what, got.TrafficAccessToken, want)
				case tc.wantToken && *got.TrafficAccessToken == got.EnvdAccessToken:
					t.Fatalf("%s: the traffic token is the envd token", what)
				case !tc.wantToken && strings.Contains(string(raw), "trafficAccessToken"):
					t.Fatalf("%s: an insecure sandbox got a traffic token: %s", what, raw)
				}
			}
		})
	}
}

func TestCodeInterpreterTemplateDefault(t *testing.T) {
	svc, _, handler := newE2BHandlerTestEnv(t)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"code-interpreter-v1"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created sandboxResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	sb, err := svc.GetSandbox(context.Background(), created.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Image != "python:3.12-slim" || created.TemplateID != "code-interpreter-v1" {
		t.Fatalf("image %q template %q", sb.Image, created.TemplateID)
	}
	if got := loadTemplateMap(`{"code-interpreter-v1":"ghcr.io/acme/ci:1"}`, nil)["code-interpreter-v1"]; got != "ghcr.io/acme/ci:1" {
		t.Fatalf("operator mapping lost: %q", got)
	}
}

func TestInterpreterCalls(t *testing.T) {
	calls := InterpreterCalls()
	want := map[string]bool{
		"POST /interpreter/e2b/execute":             true,
		"POST /interpreter/e2b/contexts":            true,
		"GET /interpreter/e2b/contexts":             true,
		"DELETE /interpreter/e2b/contexts/c1":       true,
		"POST /interpreter/e2b/contexts/c1/restart": true,
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %+v", calls)
	}
	for _, c := range calls {
		if !want[c.Method+" "+c.Path] {
			t.Fatalf("unexpected call %s %s", c.Method, c.Path)
		}
	}
}
