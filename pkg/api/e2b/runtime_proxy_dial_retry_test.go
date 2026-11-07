package e2b

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// I1 on E2B's own runtime proxy: envd that refuses the first connect and
// listens by the retry is reached, the request body arrives once, and O4
// counts the call once.
func TestRuntimeProxyRetriesARefusedDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()

	var mu sync.Mutex
	var bodies []string
	envd := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	listen := func() {
		l, err := net.Listen("tcp", addr.String())
		if err != nil {
			t.Errorf("envd listen: %v", err)
			return
		}
		srv := httptest.NewUnstartedServer(envd)
		_ = srv.Listener.Close()
		srv.Listener = l
		srv.Start()
		t.Cleanup(srv.Close)
	}

	runtime := newFakeE2BRuntime()
	runtime.containerIP = "127.0.0.1"
	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: addr.Port})
	createResp := httptest.NewRecorder()
	handler.ServeHTTP(createResp, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","secure":true}`)))
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d %s", createResp.Code, createResp.Body.String())
	}
	var created sandboxResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	var connects atomic.Int64
	var once sync.Once
	const payload = `{"path":"/home/user/once.txt"}`
	req := httptest.NewRequest(http.MethodPost, "/e2b/runtime/filesystem.Filesystem/Stat", strings.NewReader(payload))
	req.Header.Set("E2b-Sandbox-Id", created.SandboxID)
	req.Header.Set("X-Access-Token", created.EnvdAccessToken)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		ConnectStart: func(string, string) { connects.Add(1) },
		ConnectDone: func(_, _ string, err error) {
			if errors.Is(err, syscall.ECONNREFUSED) {
				once.Do(listen)
			}
		},
	}))
	before := e2bToolboxCallCount("files", "2xx")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("runtime status = %d %s, want 200 from envd that listened by the retry", resp.Code, resp.Body.String())
	}
	if n := connects.Load(); n != 2 {
		t.Fatalf("connects = %d, want 2 (refused, then connected)", n)
	}
	mu.Lock()
	got := append([]string(nil), bodies...)
	mu.Unlock()
	if len(got) != 1 || got[0] != payload {
		t.Fatalf("envd got bodies %q, want one %q", got, payload)
	}
	if n := e2bToolboxCallCount("files", "2xx"); n != before+1 {
		t.Fatalf("O4 counted the retried call %d times, want once", n-before)
	}
}
