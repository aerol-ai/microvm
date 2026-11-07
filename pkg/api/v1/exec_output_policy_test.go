package v1

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ER5 on the v1 path: the toolbox pass-through the SDKs use for exec fills
// in the operator's default, lowers a larger cap, also on the prefixed path
// toolboxd strips, and refuses with 413 a body too large to read.
func TestToolboxProxyAppliesOperatorExecOutputLimits(t *testing.T) {
	var mu sync.Mutex
	var got models.ExecRequest
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		got = models.ExecRequest{}
		_ = json.NewDecoder(r.Body).Decode(&got)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stdout":"","stderr":"","exit_code":0,"duration_ms":1}`))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	h, db := newProxyTestHandler(t, config.Config{ToolboxPort: port, ExecOutputDefaultBytes: 1024, ExecOutputMaxBytes: 1 << 20})
	createProxySandbox(t, db, "sb-er5", host, "toolbox-secret")

	send := func(path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/sb-er5/toolbox/"+path, strings.NewReader(body))
		req.SetPathValue("id", "sb-er5")
		req.SetPathValue("path", path)
		h.toolboxProxy(rr, req)
		return rr
	}
	for _, tc := range []struct {
		name, path, body string
		wantOut, wantErr int64
	}{
		{name: "default filled in", path: "process/execute", body: `{"command":"ls"}`, wantOut: 1024, wantErr: 1024},
		{name: "larger cap lowered", path: "process/execute", body: `{"command":"ls","max_stdout_bytes":1073741824,"max_stderr_bytes":5}`, wantOut: 1 << 20, wantErr: 5},
		{name: "prefixed path lowered too", path: "sb-er5/process/execute", body: `{"command":"ls","max_stdout_bytes":1073741824}`, wantOut: 1 << 20, wantErr: 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rr := send(tc.path, tc.body); rr.Code != http.StatusOK {
				t.Fatalf("status = %d %s", rr.Code, rr.Body.String())
			}
			mu.Lock()
			defer mu.Unlock()
			if got.Command != "ls" || got.MaxStdoutBytes != tc.wantOut || got.MaxStderrBytes != tc.wantErr {
				t.Fatalf("toolboxd got %+v, want caps %d/%d", got, tc.wantOut, tc.wantErr)
			}
		})
	}

	mu.Lock()
	before := calls
	mu.Unlock()
	rr := send("process/execute", `{"command":"`+strings.Repeat("x", 9<<20)+`"}`)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized exec = %d %s, want 413", rr.Code, rr.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != before {
		t.Fatal("an oversized exec reached toolboxd")
	}
}
