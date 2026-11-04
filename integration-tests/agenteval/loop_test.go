package agenteval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/agentmcp"
	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
)

// fakeModel is a scripted Messages API: each reply is decided from the
// request it answers, so the test also checks what the loop sent.
type fakeModel struct {
	t       *testing.T
	mu      sync.Mutex
	calls   int
	replies []func(req request) (int, any)
}

func (f *fakeModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("x-api-key") != "test-key" || r.Header.Get("anthropic-version") == "" {
		f.t.Errorf("missing auth or version header: %v", r.Header)
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		f.t.Errorf("request body: %v", err)
	}
	if f.calls >= len(f.replies) {
		f.t.Errorf("unexpected model call %d", f.calls+1)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	status, body := f.replies[f.calls](req)
	f.calls++
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func toolUse(id, name string, input map[string]any) block {
	raw, _ := json.Marshal(input)
	return block{Type: "tool_use", ID: id, Name: name, Input: raw}
}

// lastToolResult is the tool_result the loop sent back for id.
func lastToolResult(t *testing.T, req request, id string) block {
	t.Helper()
	last := req.Messages[len(req.Messages)-1]
	for _, b := range last.Content {
		if b.Type == "tool_result" && b.ToolUseID == id {
			return b
		}
	}
	t.Fatalf("no tool_result for %s in %+v", id, last)
	return block{}
}

func connectFake(t *testing.T) *mcp.ClientSession {
	t.Helper()
	fake := agenttoolstest.New(t)
	tools, err := agenttools.New(agenttools.Config{APIURL: fake.URL, Token: agenttoolstest.Token, Source: agenttools.SourceMCP})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := agentmcp.New(tools, agentmcp.Options{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agenteval-test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return cs
}

func TestConversationRunsToolsUntilAnswer(t *testing.T) {
	model := &fakeModel{t: t}
	model.replies = []func(request) (int, any){
		// An overloaded API is retried, not reported.
		func(request) (int, any) { return 529, map[string]any{"type": "error"} },
		func(req request) (int, any) {
			var names []string
			for _, tool := range req.Tools {
				names = append(names, tool.Name)
				if len(tool.InputSchema) == 0 || tool.Description == "" {
					t.Errorf("tool %s sent without description or schema", tool.Name)
				}
			}
			if !strings.Contains(strings.Join(names, ","), "sandbox_create") || req.System == "" || req.Model != "test-model" {
				t.Errorf("first request: tools %v, system %q, model %q", names, req.System, req.Model)
			}
			return 200, response{StopReason: "tool_use", Content: []block{
				{Type: "text", Text: "Creating it."},
				toolUse("tu1", "sandbox_create", map[string]any{"name": "evalbox", "image": "alpine"}),
			}}
		},
		func(req request) (int, any) {
			if r := lastToolResult(t, req, "tu1"); r.IsError {
				t.Errorf("sandbox_create failed: %s", r.Content)
			}
			return 200, response{StopReason: "tool_use", Content: []block{
				toolUse("tu2", "exec", map[string]any{"sandbox": "evalbox", "command": "echo 42"}),
				toolUse("tu3", "exec", map[string]any{"sandbox": "no-such-box", "command": "true"}),
			}}
		},
		func(req request) (int, any) {
			if r := lastToolResult(t, req, "tu2"); r.IsError || !strings.Contains(r.Content, "42") {
				t.Errorf("exec result = %+v", r)
			}
			if r := lastToolResult(t, req, "tu3"); !r.IsError {
				t.Errorf("a tool error must reach the model as is_error: %+v", r)
			}
			return 200, response{StopReason: "end_turn", Content: []block{{Type: "text", Text: "It printed 42."}}}
		},
	}
	api := httptest.NewServer(model)
	defer api.Close()

	ctx := context.Background()
	conv, err := NewConversation(ctx, &Anthropic{APIKey: "test-key", Model: "test-model", URL: api.URL, Backoff: 1}, connectFake(t), "system prompt")
	if err != nil {
		t.Fatal(err)
	}
	answer, err := conv.Ask(ctx, "create a box and run echo 42")
	if err != nil {
		t.Fatal(err)
	}
	if answer != "It printed 42." {
		t.Fatalf("answer = %q", answer)
	}
	if len(conv.Steps) != 3 || !conv.Called("exec") || conv.Called("read_file") {
		t.Fatalf("steps:\n%s", conv.Summary())
	}
	if conv.Steps[1].Structured["exit_code"] != float64(0) || !strings.Contains(conv.Summary(), "-> error") {
		t.Fatalf("steps:\n%s", conv.Summary())
	}
}

func TestConversationLimitsAndErrors(t *testing.T) {
	ctx := context.Background()
	session := connectFake(t)

	// A model that never stops calling tools ends at MaxTurns.
	looping := &fakeModel{t: t}
	for range 2 {
		looping.replies = append(looping.replies, func(request) (int, any) {
			return 200, response{Content: []block{toolUse("tu", "sandbox_list", map[string]any{})}}
		})
	}
	api := httptest.NewServer(looping)
	defer api.Close()
	conv, err := NewConversation(ctx, &Anthropic{APIKey: "test-key", Model: "m", URL: api.URL}, session, "")
	if err != nil {
		t.Fatal(err)
	}
	conv.MaxTurns = 2
	if _, err := conv.Ask(ctx, "loop"); err == nil || !strings.Contains(err.Error(), "no final answer") {
		t.Fatalf("looping model = %v", err)
	}

	// A 4xx is reported, not retried.
	bad := &fakeModel{t: t, replies: []func(request) (int, any){
		func(request) (int, any) { return 400, map[string]any{"error": "bad request"} },
	}}
	api2 := httptest.NewServer(bad)
	defer api2.Close()
	conv, _ = NewConversation(ctx, &Anthropic{APIKey: "test-key", Model: "m", URL: api2.URL}, session, "")
	if _, err := conv.Ask(ctx, "x"); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("400 = %v", err)
	}
	if truncate("abcdef", 3) != "abc..." || truncate("ab", 3) != "ab" {
		t.Fatal("truncate")
	}
}
