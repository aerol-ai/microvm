package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// execAgent is a fake sandboxd whose toolbox plays an agent listing
// features on /version (nil: an agent too old to list any).
type execAgent struct {
	mu       sync.Mutex
	features []string
	result   map[string]any
	calls    []string
	bodies   []map[string]any
}

func (a *execAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, r.Method+" "+r.URL.Path)
	switch r.URL.Path {
	case "/v1/sandboxes/sb-1/toolbox/version":
		body := map[string]any{"version": "0.6.11"}
		if a.features != nil {
			body["features"] = a.features
		}
		_ = json.NewEncoder(w).Encode(body)
	case "/v1/sandboxes/sb-1/toolbox/process/execute":
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		a.bodies = append(a.bodies, body)
		result := map[string]any{"stdout": "", "stderr": "", "exit_code": 0, "duration_ms": 1}
		for k, v := range a.result {
			result[k] = v
		}
		_ = json.NewEncoder(w).Encode(result)
	default:
		http.NotFound(w, r)
	}
}

func newExecAgent(t *testing.T, features []string, result map[string]any) (*Client, *execAgent) {
	t.Helper()
	agent := &execAgent{features: features, result: result}
	server := httptest.NewServer(agent)
	t.Cleanup(server.Close)
	return NewClient(server.URL, ClientOptions{PATToken: "t", HTTPClient: server.Client()}), agent
}

// E1 + ER4: output caps go out only after the agent listed them, and the
// truncated flags come back.
func TestExecOutputCaps(t *testing.T) {
	ctx := context.Background()
	client, agent := newExecAgent(t, []string{"exec.max_output_bytes"}, map[string]any{"stdout": "aaaa", "stdout_truncated": true})
	res, err := client.Exec(ctx, "sb-1", ExecRequest{Command: "yes a", MaxStdoutBytes: 4, MaxStderrBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !res.StdoutTruncated || res.StderrTruncated || res.Stdout != "aaaa" {
		t.Fatalf("result = %+v", res)
	}
	if len(agent.calls) != 2 || agent.calls[0] != "GET /v1/sandboxes/sb-1/toolbox/version" {
		t.Fatalf("calls = %v", agent.calls)
	}
	if got := agent.bodies[0]; got["max_stdout_bytes"] != float64(4) || got["max_stderr_bytes"] != float64(100) {
		t.Fatalf("exec body = %v", got)
	}

	// The feature is cached: the next capped exec makes no /version call.
	if _, err := client.Exec(ctx, "sb-1", ExecRequest{Command: "ls", MaxStderrBytes: 1}); err != nil || len(agent.calls) != 3 {
		t.Fatalf("second exec: err=%v calls=%v", err, agent.calls)
	}
}

// ER4 mixed-version: an agent that does not list the caps gets no exec at
// all; the call fails with ErrUnsupportedFeature.
func TestExecOutputCapsRefusedByOlderAgent(t *testing.T) {
	for _, features := range [][]string{nil, {}, {"files.copy"}} {
		client, agent := newExecAgent(t, features, nil)
		_, err := client.Exec(context.Background(), "sb-1", ExecRequest{Command: "yes", MaxStdoutBytes: 1024})
		var unsupported *UnsupportedFeatureError
		if !errors.Is(err, ErrUnsupportedFeature) || !errors.As(err, &unsupported) || unsupported.Features[0] != "exec.max_output_bytes" {
			t.Fatalf("features %v: err = %v", features, err)
		}
		if len(agent.bodies) != 0 {
			t.Fatalf("features %v: the exec was sent: %v", features, agent.calls)
		}
	}
}

func TestExecWithoutCapsSkipsTheVersionCall(t *testing.T) {
	client, agent := newExecAgent(t, nil, nil)
	res, err := client.Exec(context.Background(), "sb-1", ExecRequest{Command: "ls"})
	if err != nil || res.StdoutTruncated || res.StderrTruncated {
		t.Fatalf("exec = %+v, %v", res, err)
	}
	if len(agent.calls) != 1 || agent.calls[0] != "POST /v1/sandboxes/sb-1/toolbox/process/execute" {
		t.Fatalf("calls = %v", agent.calls)
	}
	if _, ok := agent.bodies[0]["max_stdout_bytes"]; ok {
		t.Fatalf("uncapped exec sent a cap: %v", agent.bodies[0])
	}
}
