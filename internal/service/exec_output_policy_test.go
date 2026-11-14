package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestIsBufferedExecPath(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/process/execute", true},
		{http.MethodPost, "process/execute", true},
		// toolboxd strips one leading segment in front of a known path.
		{http.MethodPost, "/sb-1/process/execute", true},
		{http.MethodPost, "/anything/process/execute", true},
		{http.MethodPost, "//process/execute", true},
		{http.MethodPost, "/process/./execute", true},
		{http.MethodPost, "/process/execute/", true},
		{http.MethodGet, "/process/execute", false},
		{http.MethodPost, "/process/exec/stream", false},
		{http.MethodPost, "/process/code-run", false},
		{http.MethodPost, "/files/upload", false},
		{http.MethodPost, "/process/execute2", false},
	} {
		if got := isBufferedExecPath(tc.method, tc.path); got != tc.want {
			t.Errorf("isBufferedExecPath(%s %q) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestClampOutputCap(t *testing.T) {
	for _, tc := range []struct {
		requested, def, max int64
		want                int64
		ok                  bool
	}{
		{0, 0, 0, 0, true},
		{0, 100, 0, 100, true},
		{50, 100, 0, 50, true},
		{500, 100, 0, 500, true},
		{0, 0, 1000, 1000, true},
		{0, 100, 1000, 100, true},
		{999, 100, 1000, 999, true},
		{1000, 100, 1000, 1000, true},
		{5000, 100, 1000, 1000, true},
		{-1, 100, 1000, -1, false},
	} {
		got, ok := clampOutputCap(tc.requested, tc.def, tc.max)
		if got != tc.want || ok != tc.ok {
			t.Errorf("clampOutputCap(%d, def %d, max %d) = %d %v, want %d %v", tc.requested, tc.def, tc.max, got, ok, tc.want, tc.ok)
		}
	}
}

// decodeCaps reads a body the way toolboxd does.
func decodeCaps(t *testing.T, body []byte) models.ExecRequest {
	t.Helper()
	var req models.ExecRequest
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&req); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return req
}

func TestClampExecOutputBody(t *testing.T) {
	for _, tc := range []struct {
		name               string
		body               string
		def, max           int64
		wantOut, wantErr   int64
		unchanged          bool
		wantFieldsIncluded []string
	}{
		{name: "default fills both", body: `{"command":"ls"}`, def: 100, wantOut: 100, wantErr: 100},
		{name: "default keeps the caller's own cap", body: `{"command":"ls","max_stdout_bytes":7}`, def: 100, wantOut: 7, wantErr: 100},
		{name: "max lowers a larger cap", body: `{"command":"ls","max_stdout_bytes":5000,"max_stderr_bytes":20}`, max: 1000, wantOut: 1000, wantErr: 20},
		{name: "max applies with no cap at all", body: `{"command":"ls"}`, max: 1000, wantOut: 1000, wantErr: 1000},
		{name: "default and max", body: `{"command":"ls","max_stderr_bytes":99999}`, def: 10, max: 1000, wantOut: 10, wantErr: 1000},
		{name: "already within", body: `{"command":"ls","max_stdout_bytes":5,"max_stderr_bytes":6}`, def: 10, max: 1000, wantOut: 5, wantErr: 6, unchanged: true},
		{name: "null cap is no cap", body: `{"command":"ls","max_stdout_bytes":null}`, def: 10, wantOut: 10, wantErr: 10},
		// encoding/json matches names case-insensitively, so every spelling
		// is replaced, not just the canonical one.
		{name: "upper-case spelling cannot slip past the max", body: `{"command":"ls","MAX_STDOUT_BYTES":999999}`, max: 1000, wantOut: 1000, wantErr: 1000},
		{name: "two spellings, last wins in toolboxd", body: `{"command":"ls","max_stdout_bytes":10,"Max_Stdout_Bytes":999999}`, max: 1000, wantOut: 1000, wantErr: 1000},
		// toolboxd decodes the first JSON value and ignores the rest.
		{name: "trailing value is dropped", body: `{"command":"ls","max_stdout_bytes":999999} {"x":1}`, max: 1000, wantOut: 1000, wantErr: 1000},
		{name: "other fields kept, including unknown ones", body: `{"command":"echo <a> & b","workdir":"/tmp","env":{"A":"1"},"timeout_seconds":9,"argv":["x","y"],"future":{"k":[1,2]}}`,
			def: 10, wantOut: 10, wantErr: 10, wantFieldsIncluded: []string{`"command":"echo <a> & b"`, `"workdir":"/tmp"`, `"env":{"A":"1"}`, `"timeout_seconds":9`, `"argv":["x","y"]`, `"future":{"k":[1,2]}`}},
		// What toolboxd cannot decode, or refuses, passes through for it to answer.
		{name: "negative cap passes through", body: `{"command":"ls","max_stdout_bytes":-1}`, max: 1000, unchanged: true},
		{name: "not JSON", body: `command=ls`, max: 1000, unchanged: true},
		{name: "wrong type", body: `{"command":"ls","max_stdout_bytes":"big"}`, max: 1000, unchanged: true},
		{name: "fraction", body: `{"command":"ls","max_stdout_bytes":1.5}`, max: 1000, unchanged: true},
		{name: "array", body: `[1,2]`, max: 1000, unchanged: true},
		{name: "null body gets caps", body: `null`, max: 1000, wantOut: 1000, wantErr: 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := clampExecOutputBody([]byte(tc.body), tc.def, tc.max)
			if err != nil {
				t.Fatal(err)
			}
			if tc.unchanged {
				if string(out) != tc.body {
					t.Fatalf("body = %s, want it unchanged", out)
				}
				return
			}
			got := decodeCaps(t, out)
			if got.MaxStdoutBytes != tc.wantOut || got.MaxStderrBytes != tc.wantErr {
				t.Fatalf("caps = %d/%d, want %d/%d (body %s)", got.MaxStdoutBytes, got.MaxStderrBytes, tc.wantOut, tc.wantErr, out)
			}
			for _, field := range tc.wantFieldsIncluded {
				if !strings.Contains(string(out), field) {
					t.Fatalf("body %s lost %s", out, field)
				}
			}
			if strings.Contains(string(out), "999999") {
				t.Fatalf("body %s still carries the caller's larger cap", out)
			}
		})
	}
}

func TestApplyExecOutputPolicy(t *testing.T) {
	old := maxExecPolicyBodyBytes
	maxExecPolicyBodyBytes = 64
	t.Cleanup(func() { maxExecPolicyBodyBytes = old })
	read := func(t *testing.T, r io.Reader) string {
		t.Helper()
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	off := &Service{}
	in := strings.NewReader(`{"command":"ls"}`)
	if got, err := off.applyExecOutputPolicy(http.MethodPost, "/process/execute", in); err != nil || got != io.Reader(in) || in.Len() == 0 {
		t.Fatal("policy off: body was read or replaced")
	}

	on := &Service{}
	on.cfg.ExecOutputMaxBytes = 1000
	in = strings.NewReader(`{"command":"ls"}`)
	if got, _ := on.applyExecOutputPolicy(http.MethodPost, "/files/upload", in); got != io.Reader(in) || in.Len() == 0 {
		t.Fatal("non-exec path: body was read or replaced")
	}
	if got, _ := on.applyExecOutputPolicy(http.MethodPost, "/process/execute", nil); got != nil {
		t.Fatal("nil body replaced")
	}
	got, err := on.applyExecOutputPolicy(http.MethodPost, "/process/execute", strings.NewReader(`{"command":"ls"}`))
	if err != nil || !strings.Contains(read(t, got), `"max_stdout_bytes":1000`) {
		t.Fatalf("exec body not clamped (err %v)", err)
	}

	big := `{"command":"` + strings.Repeat("x", 100) + `"}`
	if _, err := on.applyExecOutputPolicy(http.MethodPost, "/process/execute", strings.NewReader(big)); !errors.Is(err, ErrExecRequestTooLarge) {
		t.Fatalf("oversized body with a max = %v, want ErrExecRequestTooLarge", err)
	}
	defaultOnly := &Service{}
	defaultOnly.cfg.ExecOutputDefaultBytes = 10
	got, err = defaultOnly.applyExecOutputPolicy(http.MethodPost, "/process/execute", strings.NewReader(big))
	if err != nil || read(t, got) != big {
		t.Fatalf("oversized body with only a default must pass through whole (err %v)", err)
	}

	failing := &Service{}
	failing.cfg.ExecOutputMaxBytes = 1
	if _, err := failing.applyExecOutputPolicy(http.MethodPost, "/process/execute", errReader{}); err == nil {
		t.Fatal("read error swallowed")
	}
}

// ER5 at the two service chokepoints: the reverse proxy (v1's toolbox
// pass-through, Daytona's process routes) and RoundTripToolbox (Daytona
// executeCommand, Runloop one-shot commands) both fill in the default and
// lower a larger cap before toolboxd sees the body.
func TestExecOutputPolicyAtBothToolboxChokepoints(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var bodies []string
	var lengths []int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		lengths = append(lengths, r.ContentLength)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"stdout":"","stderr":"","exit_code":0,"duration_ms":1}`)
	}))
	defer ts.Close()

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	var port int
	fmt.Sscanf(strings.Split(ts.URL, ":")[2], "%d", &port)
	svc.cfg.ToolboxPort = port
	svc.cfg.ExecOutputDefaultBytes = 4096
	svc.cfg.ExecOutputMaxBytes = 65536
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-er5", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted,
		ToolboxToken: "tok", ContainerIP: "127.0.0.1", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	last := func() (models.ExecRequest, int64) {
		mu.Lock()
		defer mu.Unlock()
		return decodeCaps(t, []byte(bodies[len(bodies)-1])), lengths[len(lengths)-1]
	}

	for _, tc := range []struct {
		name             string
		body             string
		wantOut, wantErr int64
	}{
		{name: "default filled in", body: `{"command":"ls"}`, wantOut: 4096, wantErr: 4096},
		{name: "larger cap clamped", body: `{"command":"ls","max_stdout_bytes":1048576,"max_stderr_bytes":10}`, wantOut: 65536, wantErr: 10},
	} {
		t.Run("reverse proxy: "+tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://x/process/execute", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			if err := svc.ServeToolboxReverseProxy(WithToolboxSurface(ctx, ToolboxSurfaceV1), "sb-er5", rec, req, "/process/execute"); err != nil {
				t.Fatal(err)
			}
			got, length := last()
			if got.MaxStdoutBytes != tc.wantOut || got.MaxStderrBytes != tc.wantErr || got.Command != "ls" {
				t.Fatalf("toolboxd got %+v, want caps %d/%d", got, tc.wantOut, tc.wantErr)
			}
			if mu.Lock(); length != int64(len(bodies[len(bodies)-1])) {
				mu.Unlock()
				t.Fatalf("Content-Length %d does not match the rewritten body", length)
			}
			mu.Unlock()
		})
		t.Run("round trip: "+tc.name, func(t *testing.T) {
			resp, err := svc.RoundTripToolbox(WithToolboxSurface(ctx, ToolboxSurfaceDaytona), "sb-er5", http.MethodPost, "/process/execute", nil, strings.NewReader(tc.body), http.Header{"Content-Type": {"application/json"}})
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			got, _ := last()
			if got.MaxStdoutBytes != tc.wantOut || got.MaxStderrBytes != tc.wantErr {
				t.Fatalf("toolboxd got %+v, want caps %d/%d", got, tc.wantOut, tc.wantErr)
			}
		})
	}

	// The prefixed form toolboxd also runs as an exec is clamped too.
	req := httptest.NewRequest(http.MethodPost, "http://x/sb-er5/process/execute", strings.NewReader(`{"command":"ls","max_stdout_bytes":999999999}`))
	if err := svc.ServeToolboxReverseProxy(ctx, "sb-er5", httptest.NewRecorder(), req, "/sb-er5/process/execute"); err != nil {
		t.Fatal(err)
	}
	if got, _ := last(); got.MaxStdoutBytes != 65536 {
		t.Fatalf("prefixed exec path not clamped: %+v", got)
	}

	// Other toolbox calls are forwarded byte for byte.
	mu.Lock()
	before := len(bodies)
	mu.Unlock()
	req = httptest.NewRequest(http.MethodPost, "http://x/files/move", strings.NewReader(`{"max_stdout_bytes":999999999}`))
	if err := svc.ServeToolboxReverseProxy(ctx, "sb-er5", httptest.NewRecorder(), req, "/files/move"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(bodies) != before+1 || bodies[before] != `{"max_stdout_bytes":999999999}` {
		mu.Unlock()
		t.Fatalf("non-exec body changed: %v", bodies[before:])
	}
	mu.Unlock()

	// A body too large to clamp is refused before the sandbox is reached,
	// and counted as a 413.
	old := maxExecPolicyBodyBytes
	maxExecPolicyBodyBytes = 32
	t.Cleanup(func() { maxExecPolicyBodyBytes = old })
	before413 := toolboxCallCount("v1", "exec", "4xx")
	mu.Lock()
	before = len(bodies)
	mu.Unlock()
	req = httptest.NewRequest(http.MethodPost, "http://x/process/execute", strings.NewReader(`{"command":"`+strings.Repeat("x", 64)+`"}`))
	err := svc.ServeToolboxReverseProxy(WithToolboxSurface(ctx, ToolboxSurfaceV1), "sb-er5", httptest.NewRecorder(), req, "/process/execute")
	if !errors.Is(err, ErrExecRequestTooLarge) {
		t.Fatalf("oversized exec = %v, want ErrExecRequestTooLarge", err)
	}
	if got := toolboxCallCount("v1", "exec", "4xx"); got != before413+1 {
		t.Fatalf("oversized exec not counted as 4xx: %d", got)
	}
	if _, err := svc.RoundTripToolbox(ctx, "sb-er5", http.MethodPost, "/process/execute", nil, strings.NewReader(`{"command":"`+strings.Repeat("x", 64)+`"}`), nil); !errors.Is(err, ErrExecRequestTooLarge) {
		t.Fatalf("oversized round trip = %v, want ErrExecRequestTooLarge", err)
	}
	mu.Lock()
	if len(bodies) != before {
		mu.Unlock()
		t.Fatal("an oversized exec reached toolboxd")
	}
	mu.Unlock()
	if got := toolboxErrorStatus(fmt.Errorf("wrap: %w", ErrExecRequestTooLarge)); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("toolboxErrorStatus = %d, want 413", got)
	}
}
