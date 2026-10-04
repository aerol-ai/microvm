package remotemcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// TestInProcessTransportStreams is the C1 required proof: headers and the
// first bytes reach the client before the handler finishes, and a large body
// is never held whole — the handler is at most one write ahead of the reader.
func TestInProcessTransportStreams(t *testing.T) {
	release := make(chan struct{})
	var written atomic.Int64
	chunk := bytes.Repeat([]byte("x"), 64*1024)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.RemoteAddr != "203.0.113.9:1234" || r.RequestURI != "/v1/big?x=1" {
			http.Error(w, "request not carried through", http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Test", "1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		<-release
		for i := 0; i < 128; i++ { // 8 MiB
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	})
	client := &http.Client{Transport: &inProcessTransport{handler: handler, remoteAddr: "203.0.113.9:1234"}}
	req, _ := http.NewRequest(http.MethodGet, "http://in-process/v1/big?x=1", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("RoundTrip returned before the handler finished? %v", err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Test") != "1" {
		t.Fatalf("status %d headers %v", resp.StatusCode, resp.Header)
	}
	first := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "first" {
		t.Fatalf("first bytes = %q, %v", first, err)
	}
	close(release)
	// Read 1 MiB, then check the handler hasn't run ahead.
	if _, err := io.ReadFull(resp.Body, make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if ahead := written.Load() - (1 << 20); ahead > int64(len(chunk)) {
		t.Fatalf("the handler wrote %d bytes ahead of the reader; the body is being buffered", ahead)
	}
	// The client stops early (the 4 MiB limit case): the handler's next write fails.
	_ = resp.Body.Close()
	time.Sleep(50 * time.Millisecond)
	if total := written.Load(); total >= 128*int64(len(chunk)) {
		t.Fatalf("the handler wrote all %d bytes after the reader closed", total)
	}
}

func TestInProcessTransportEdges(t *testing.T) {
	panicking := &http.Client{Transport: &inProcessTransport{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })}}
	resp, err := panicking.Get("http://in-process/x")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("panic status = %d", resp.StatusCode)
	}
	if _, err := io.ReadAll(resp.Body); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("panic body error = %v", err)
	}
	silent := &http.Client{Transport: &inProcessTransport{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}}
	resp, err = silent.Post("http://in-process/x", "text/plain", strings.NewReader("body"))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("empty handler = %v, %v", resp, err)
	}
	_ = resp.Body.Close()
	block := make(chan struct{})
	defer close(block)
	blocked := &http.Client{Transport: &inProcessTransport{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block })}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://in-process/x", nil)
	if _, err := blocked.Do(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled before headers = %v", err)
	}
	w := &pipeResponseWriter{header: http.Header{}, headerSent: make(chan struct{})}
	w.WriteHeader(http.StatusContinue)
	select {
	case <-w.headerSent:
		t.Fatal("1xx must not complete the response header")
	default:
	}
}

// TestInProcessTransportUnknownLengthBody: the SDK streams uploads with a
// body of unknown length, which a client request writes as ContentLength 0.
// sandboxd forwards toolbox calls with httputil.ReverseProxy, which drops a
// body whose server-side ContentLength is 0, so remote write_file reached
// toolboxd with nothing in it. The body must arrive whole.
func TestInProcessTransportUnknownLengthBody(t *testing.T) {
	var got []byte
	toolbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	}))
	defer toolbox.Close()
	target, _ := url.Parse(toolbox.URL)
	client := &http.Client{Transport: &inProcessTransport{handler: httputil.NewSingleHostReverseProxy(target)}}

	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, "streamed upload")
		_ = pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, "http://in-process/upload", pr)
	if req.ContentLength != 0 {
		t.Fatalf("precondition: a pipe body has ContentLength %d, want 0", req.ContentLength)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if string(got) != "streamed upload" {
		t.Fatalf("toolbox received %q, want the whole body", got)
	}

	// An empty request still arrives empty.
	resp, err = client.Post("http://in-process/upload", "text/plain", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(got) != 0 {
		t.Fatalf("empty request arrived as %q", got)
	}
}

type endpoint struct {
	t      *testing.T
	fake   *agenttoolstest.Server
	server *httptest.Server
	logs   *bytes.Buffer
}

func newEndpoint(t *testing.T, cfg Config) *endpoint {
	t.Helper()
	fake := agenttoolstest.New(t)
	logs := &bytes.Buffer{}
	var logMu sync.Mutex
	cfg.Logger = slog.New(slog.NewJSONHandler(lockedWriter{w: logs, mu: &logMu}, nil))
	h := New(cfg, func() http.Handler { return fake.Config.Handler })
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+agenttoolstest.Token {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	srv := httptest.NewServer(h.Wrap(auth))
	t.Cleanup(srv.Close)
	return &endpoint{t: t, fake: fake, server: srv, logs: logs}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

type headerTransport struct{ headers map[string]string }

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (e *endpoint) connect(query string) *mcp.ClientSession {
	e.t.Helper()
	transport := &mcp.StreamableClientTransport{
		Endpoint:   e.server.URL + Path + "?" + query,
		HTTPClient: &http.Client{Transport: headerTransport{map[string]string{"Authorization": "Bearer " + agenttoolstest.Token}}},
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "remote-test"}, nil).Connect(context.Background(), transport, nil)
	if err != nil {
		e.t.Fatalf("connect %s: %v", query, err)
	}
	e.t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func (e *endpoint) post(query string, headers map[string]string) *http.Response {
	e.t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	req, _ := http.NewRequest(http.MethodPost, e.server.URL+Path+"?"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+agenttoolstest.Token)
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func callText(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (*mcp.CallToolResult, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return res, b.String()
}

func structured(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// TestRemoteQueryParameters pins CF1/CF2: options come from the query, an
// invalid one is a 400 naming it, sandbox is required, and the fleet tools
// are never offered remotely.
func TestRemoteQueryParameters(t *testing.T) {
	e := newEndpoint(t, Config{})
	for query, want := range map[string]string{
		"":                              "remote MCP requires ?sandbox=<name>",
		"sandbox=a&toolsets=shell":      "toolsets",
		"sandbox=a&create-if-missing=1": "create-if-missing",
		"sandbox=a&read_only=maybe":     "read_only",
		"sandbox=sb-0123456789abcdef&create_if_missing=true": "sandbox",
	} {
		resp := e.post(query, nil)
		var body models.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body.Error, want) {
			t.Fatalf("?%s = %d %q, want 400 naming %q", query, resp.StatusCode, body.Error, want)
		}
	}
	cs := e.connect("sandbox=my-agent&create_if_missing=true&toolsets=all")
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if strings.HasPrefix(tool.Name, "sandbox_") {
			t.Fatalf("remote tools/list offered %s", tool.Name)
		}
	}
	if len(tools.Tools) != 11 {
		t.Fatalf("remote all toolsets = %d tools", len(tools.Tools))
	}
	ro := e.connect("sandbox=my-agent&read_only=true&toolsets=all")
	tools, _ = ro.ListTools(context.Background(), nil)
	for _, tool := range tools.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("read_only=true offered %s", tool.Name)
		}
	}
}

// TestRemoteOriginAndHost is the §5.7 required proof.
func TestRemoteOriginAndHost(t *testing.T) {
	e := newEndpoint(t, Config{AllowedOrigins: []string{"https://app.example.com"}})
	if resp := e.post("sandbox=a", map[string]string{"Origin": "https://evil.example"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad origin = %d, want 403", resp.StatusCode)
	}
	if resp := e.post("sandbox=a", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("no origin = %d, want 200", resp.StatusCode)
	}
	if resp := e.post("sandbox=a", map[string]string{"Origin": "https://app.example.com"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed origin = %d", resp.StatusCode)
	}
	hosts := newEndpoint(t, Config{AllowedHosts: []string{"sandbox.example.com"}})
	if resp := hosts.post("sandbox=a", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unlisted host = %d, want 403", resp.StatusCode)
	}
	if hostOnly("sandbox.example.com:443") != "sandbox.example.com" || hostOnly("bare") != "bare" {
		t.Fatal("hostOnly")
	}
}

// TestRemoteBehindLoopbackProxy: Caddy reaches sandboxd on 127.0.0.1:21212
// and forwards the API domain as Host. The go-sdk's default rebinding guard
// refused exactly that (a loopback socket with a non-loopback Host), so the
// first live cluster run got 403 on initialize for every request. The test
// server also listens on loopback, so this is the production shape.
func TestRemoteBehindLoopbackProxy(t *testing.T) {
	e := newEndpoint(t, Config{})
	if resp := e.post("sandbox=a", map[string]string{"Host": "sandbox.example.com"}); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("proxied request = %d %s, want 200", resp.StatusCode, body)
	}
	// Host pinning, when configured, is still enforced on that path.
	pinned := newEndpoint(t, Config{AllowedHosts: []string{"sandbox.example.com"}})
	if resp := pinned.post("sandbox=a", map[string]string{"Host": "sandbox.example.com"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("pinned host = %d, want 200", resp.StatusCode)
	}
	if resp := pinned.post("sandbox=a", map[string]string{"Host": "evil.example"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unpinned host = %d, want 403", resp.StatusCode)
	}
	// So is the Origin check, the browser-side rebinding defence.
	if resp := e.post("sandbox=a", map[string]string{"Host": "sandbox.example.com", "Origin": "https://evil.example"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin request = %d, want 403", resp.StatusCode)
	}
}

func TestRemoteAuthAndRateLimit(t *testing.T) {
	e := newEndpoint(t, Config{RateLimit: 1})
	before := requestCount("unauthorized")
	if resp := e.post("sandbox=a", map[string]string{"Authorization": "Bearer wrong"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token = %d", resp.StatusCode)
	}
	if requestCount("unauthorized") != before+1 {
		t.Fatal("unauthorized not counted")
	}
	// Burst is 2 at 1 req/s; the third immediate request is limited.
	codes := []int{e.post("sandbox=a", nil).StatusCode, e.post("sandbox=a", nil).StatusCode, e.post("sandbox=a", nil).StatusCode}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("rate limit codes = %v", codes)
	}
	l := newTokenLimiter(1000)
	for i := 0; i < maxTokenBuckets+5; i++ {
		l.allow(strings.Repeat("t", i))
	}
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n > maxTokenBuckets+5 {
		t.Fatalf("buckets = %d", n)
	}
	if newTokenLimiter(0) != nil || !(*tokenLimiter)(nil).allow("x") {
		t.Fatal("zero rate disables the limit")
	}
}

// TestRemoteToolCall covers RR2 (created notice), buffered exec, and CF6
// (counter + one log line with no arguments).
func TestRemoteToolCall(t *testing.T) {
	e := newEndpoint(t, Config{Version: "test"})
	cs := e.connect("sandbox=my-agent&create_if_missing=true&image=alpine")
	beforeOK := toolCount("exec", "ok")
	res, text := callText(t, cs, "exec", map[string]any{"command": "echo secret-arg-value"})
	data := structured(t, res)
	if res.IsError || data["sandbox_created"] != true || !strings.Contains(text, "NOTICE: this is a newly created sandbox") {
		t.Fatalf("first remote call = %v %q", data, text)
	}
	if toolCount("exec", "ok") != beforeOK+1 {
		t.Fatal("exec ok not counted")
	}
	// A new stateless request against the existing sandbox: no flag.
	cs2 := e.connect("sandbox=my-agent&create_if_missing=true")
	res, _ = callText(t, cs2, "exec", map[string]any{"command": "echo again"})
	if structured(t, res)["sandbox_created"] != nil {
		t.Fatal("an existing sandbox must not carry sandbox_created")
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		if s.StreamDials != 0 || s.BufferedExecs != 2 {
			t.Fatalf("remote exec must be buffered (dials %d, buffered %d)", s.StreamDials, s.BufferedExecs)
		}
		if s.CreatePosts != 1 || s.LastCreate.Tags["aerolvm.created_by"] != "mcp" {
			t.Fatalf("creates %d tags %v", s.CreatePosts, s.LastCreate.Tags)
		}
	})
	// A tool error is counted as tool_error and logged.
	beforeErr := toolCount("read_file", "tool_error")
	res, _ = callText(t, cs2, "read_file", map[string]any{"path": "/missing"})
	if !res.IsError || toolCount("read_file", "tool_error") != beforeErr+1 {
		t.Fatalf("read_file error = %v", res.IsError)
	}
	logs := e.logs.String()
	if strings.Count(logs, `"msg":"mcp tool call"`) != 3 || !strings.Contains(logs, `"sandbox_id":"sb-`) || !strings.Contains(logs, `"outcome":"tool_error"`) {
		t.Fatalf("log lines = %s", logs)
	}
	if strings.Contains(logs, "secret-arg-value") || strings.Contains(logs, "echo again") {
		t.Fatal("a log line carried tool arguments")
	}
}

func TestRemoteMissingPinnedSandbox(t *testing.T) {
	e := newEndpoint(t, Config{})
	cs := e.connect("sandbox=nope")
	res, text := callText(t, cs, "exec", map[string]any{"command": "echo"})
	if !res.IsError || !strings.Contains(text, `"nope" does not exist`) {
		t.Fatalf("missing pinned = %q", text)
	}
	e.fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
	cs = e.connect("sandbox=iso")
	if res, text := callText(t, cs, "exec", map[string]any{"command": "echo"}); !res.IsError || !strings.Contains(text, "isolate") {
		t.Fatalf("isolate = %q", text)
	}
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		err     error
		outcome string
	}{
		{nil, "ok"},
		{errors.New("boom"), "api_error"},
		{context.DeadlineExceeded, "api_error"},
		{&microvm.APIError{StatusCode: 401}, "unauthorized"},
		{&microvm.APIError{StatusCode: 404}, "tool_error"},
		{&microvm.APIError{StatusCode: 501}, "tool_error"},
		{&microvm.APIError{StatusCode: 503}, "api_error"},
	} {
		if got, _ := classify(tc.err); got != tc.outcome {
			t.Fatalf("classify(%v) = %s, want %s", tc.err, got, tc.outcome)
		}
	}
	if spanError("tool_error", errors.New("x")) != nil || spanError("api_error", errors.New("x")) == nil {
		t.Fatal("spanError")
	}
}

func toolCount(tool, outcome string) int64 {
	m, ok := toolCalls.Get(tool).(*expvar.Map)
	if !ok {
		return 0
	}
	if v, ok := m.Get(outcome).(*expvar.Int); ok {
		return v.Value()
	}
	return 0
}

func requestCount(outcome string) int64 {
	if v, ok := requests.Get(outcome).(*expvar.Int); ok {
		return v.Value()
	}
	return 0
}

func TestBearerToken(t *testing.T) {
	for header, want := range map[string]string{"Bearer abc": "abc", "bearer  abc ": "abc", "Basic abc": "", "": ""} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", header)
		if got := bearerToken(r); got != want {
			t.Fatalf("bearerToken(%q) = %q", header, got)
		}
	}
}
