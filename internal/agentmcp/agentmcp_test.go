package agentmcp

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

var update = flag.Bool("update", false, "rewrite the tools/list golden files")

type env struct {
	t      *testing.T
	fake   *agenttoolstest.Server
	server *Server
	client *mcp.ClientSession
}

func newEnv(t *testing.T, opts Options) *env {
	t.Helper()
	fake := agenttoolstest.New(t)
	return connect(t, fake, opts)
}

func connect(t *testing.T, fake *agenttoolstest.Server, opts Options) *env {
	t.Helper()
	tools, err := agenttools.New(agenttools.Config{APIURL: fake.URL, Token: agenttoolstest.Token, Source: agenttools.SourceMCP})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(tools, opts, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e := connectServer(t, srv)
	e.fake = fake
	return e
}

func connectServer(t *testing.T, srv *Server) *env {
	t.Helper()
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return &env{t: t, server: srv, client: cs}
}

type callResult struct {
	isError bool
	text    string
	data    map[string]any
}

func (e *env) call(name string, args map[string]any) callResult {
	e.t.Helper()
	res, err := e.client.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		e.t.Fatalf("CallTool(%s): %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	out := callResult{isError: res.IsError, text: b.String()}
	if res.StructuredContent != nil {
		raw, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(raw, &out.data)
	}
	return out
}

func (e *env) toolNames() []string {
	e.t.Helper()
	res, err := e.client.ListTools(context.Background(), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

// TestToolsListGolden snapshots tools/list (names, descriptions, schemas,
// annotations) per mode, so any change to what the model sees is a reviewed
// diff. Regenerate with: go test ./internal/agentmcp -run Golden -update
func TestToolsListGolden(t *testing.T) {
	modes := map[string]Options{
		"unpinned_core":     {MaxCreates: DefaultMaxCreates},
		"unpinned_all":      {Toolsets: []string{"all"}},
		"pinned_core":       {Sandbox: "my-agent", CreateIfMissing: true},
		"pinned_all":        {Sandbox: "my-agent", Toolsets: []string{"all"}},
		"read_only_all":     {Toolsets: []string{"all"}, ReadOnly: true},
		"remote_pinned_all": {Sandbox: "my-agent", CreateIfMissing: true, Remote: true, Toolsets: []string{"all"}},
	}
	for name, opts := range modes {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, opts)
			res, err := e.client.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			sort.Slice(res.Tools, func(i, j int) bool { return res.Tools[i].Name < res.Tools[j].Name })
			got, err := json.MarshalIndent(res.Tools, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "tools_"+name+".golden.json")
			if *update {
				if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update): %v", err)
			}
			if string(want) != string(got)+"\n" {
				t.Fatalf("tools/list for %s changed; review and run with -update:\n%s", name, got)
			}
		})
	}
}

func TestModesShapeTheToolList(t *testing.T) {
	core := []string{"exec", "expose_port", "list_files", "read_file", "sandbox_create", "sandbox_destroy", "sandbox_list", "write_file"}
	if got := newEnv(t, Options{}).toolNames(); strings.Join(got, ",") != strings.Join(core, ",") {
		t.Fatalf("default tools = %v", got)
	}
	pinned := newEnv(t, Options{Sandbox: "box", Toolsets: []string{"all"}}).toolNames()
	for _, fleet := range []string{"sandbox_create", "sandbox_list", "sandbox_destroy"} {
		if contains(pinned, fleet) {
			t.Fatalf("pinned mode registered %s", fleet)
		}
	}
	if len(pinned) != 11 {
		t.Fatalf("pinned all = %v", pinned)
	}
	readOnly := newEnv(t, Options{Toolsets: []string{"all"}, ReadOnly: true}).toolNames()
	want := []string{"grep_files", "list_files", "process_logs", "read_file", "sandbox_list", "search_files"}
	if strings.Join(readOnly, ",") != strings.Join(want, ",") {
		t.Fatalf("read-only = %v", readOnly)
	}
	// Pinned schemas have no sandbox argument.
	e := newEnv(t, Options{Sandbox: "box"})
	res, err := e.client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		raw, _ := json.Marshal(tool.InputSchema)
		if strings.Contains(string(raw), `"sandbox"`) {
			t.Fatalf("pinned %s schema still has sandbox: %s", tool.Name, raw)
		}
	}
}

func TestCreateListDestroy(t *testing.T) {
	e := newEnv(t, Options{MaxCreates: DefaultMaxCreates})
	r := e.call("sandbox_create", map[string]any{"name": "agent", "image": "alpine", "runtime": "docker", "env": map[string]any{"A": "1"}, "cpu": 1, "memory_mb": 512})
	if r.isError || r.data["created"] != true || r.data["name"] != "agent" {
		t.Fatalf("create = %+v", r)
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		lc := s.LastCreate.Lifecycle
		if lc == nil || lc.StopIfIdleFor != 30*time.Minute || lc.DestroyIfIdleFor != 24*time.Hour {
			t.Fatalf("MCP lifecycle default = %+v", lc)
		}
		if s.LastCreate.Tags[agenttools.CreatedByTag] != "mcp" {
			t.Fatalf("provenance tag = %v", s.LastCreate.Tags)
		}
	})
	if r := e.call("sandbox_create", map[string]any{"name": "agent2", "destroy_if_idle_minutes": 90}); r.isError {
		t.Fatal(r.text)
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		if s.LastCreate.Lifecycle.DestroyIfIdleFor != 90*time.Minute {
			t.Fatalf("destroy override = %v", s.LastCreate.Lifecycle)
		}
	})
	if r := e.call("sandbox_create", map[string]any{"name": "agent", "runtime": "isolate"}); !r.isError || !strings.Contains(r.text, "runtime") {
		t.Fatalf("isolate runtime must be rejected by the schema: %+v", r)
	}
	if r := e.call("sandbox_create", map[string]any{"destroy_if_idle_minutes": -1}); !r.isError {
		t.Fatal("negative minutes")
	}
	list := e.call("sandbox_list", nil)
	if list.isError || len(list.data["sandboxes"].([]any)) != 2 {
		t.Fatalf("list = %+v", list)
	}
	row := list.data["sandboxes"].([]any)[0].(map[string]any)
	for k := range row {
		if !contains([]string{"id", "name", "status", "runtime", "created_at", "tags"}, k) {
			t.Fatalf("sandbox_list row has extra field %q", k)
		}
	}
	if r := e.call("sandbox_destroy", map[string]any{"sandbox": "agent"}); r.isError || r.data["destroyed"] != true {
		t.Fatalf("destroy = %+v", r)
	}
	if r := e.call("sandbox_destroy", map[string]any{"sandbox": "agent"}); r.isError || r.data["already_gone"] != true {
		t.Fatalf("destroy again = %+v", r)
	}
}

// TestSandboxListPages pins D15: at most 20 compact rows, limit=20 sent,
// next_page_token passed through.
func TestSandboxListPages(t *testing.T) {
	e := newEnv(t, Options{})
	for i := 0; i < 25; i++ {
		e.fake.AddSandbox(models.Sandbox{Name: "sb" + string(rune('a'+i))})
	}
	first := e.call("sandbox_list", nil)
	if len(first.data["sandboxes"].([]any)) != 20 || first.data["next_page_token"] == "" {
		t.Fatalf("first page = %d rows, token %v", len(first.data["sandboxes"].([]any)), first.data["next_page_token"])
	}
	second := e.call("sandbox_list", map[string]any{"page_token": first.data["next_page_token"]})
	if len(second.data["sandboxes"].([]any)) != 5 || second.data["next_page_token"] != nil {
		t.Fatalf("second page = %+v", second.data)
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		if !strings.Contains(s.ListQueries[0], "limit=20") {
			t.Fatalf("list query = %q, want limit=20", s.ListQueries[0])
		}
	})
}

// TestCreateCap pins CEO review C4.
func TestCreateCap(t *testing.T) {
	e := newEnv(t, Options{MaxCreates: 5})
	for i := 0; i < 5; i++ {
		if r := e.call("sandbox_create", nil); r.isError {
			t.Fatalf("create %d: %s", i, r.text)
		}
	}
	var posts int
	e.fake.Observe(func(s *agenttoolstest.Server) { posts = s.CreatePosts })
	r := e.call("sandbox_create", nil)
	if !r.isError || !strings.Contains(r.text, "create limit reached") || !strings.Contains(r.text, "create_limit") {
		t.Fatalf("6th create = %+v", r)
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		if s.CreatePosts != posts {
			t.Fatal("the capped create sent a POST")
		}
	})
	// A name that already exists isn't a create: answered at the cap.
	e.fake.AddSandbox(models.Sandbox{Name: "existing"})
	if r := e.call("sandbox_create", map[string]any{"name": "existing"}); r.isError || r.data["created"] != false {
		t.Fatalf("existing name at the cap = %+v", r)
	}
	// Creates that resolve to an existing sandbox don't count.
	e2 := newEnv(t, Options{MaxCreates: 1})
	e2.fake.AddSandbox(models.Sandbox{Name: "taken"})
	if r := e2.call("sandbox_create", map[string]any{"name": "taken"}); r.isError || r.data["created"] != false {
		t.Fatal(r.text)
	}
	if r := e2.call("sandbox_create", nil); r.isError {
		t.Fatalf("the cap counted a create that didn't happen: %s", r.text)
	}
	// 0 lifts the cap.
	e3 := newEnv(t, Options{MaxCreates: 0})
	for i := 0; i < 7; i++ {
		if r := e3.call("sandbox_create", nil); r.isError {
			t.Fatalf("unlimited create %d: %s", i, r.text)
		}
	}
}

func TestExecAndFileTools(t *testing.T) {
	e := newEnv(t, Options{Toolsets: []string{"all"}})
	box := e.fake.AddSandbox(models.Sandbox{Name: "box"})
	r := e.call("exec", map[string]any{"sandbox": "box", "command": "exit 2"})
	if r.isError || r.data["exit_code"] != float64(2) || !strings.Contains(r.text, "exit_code: 2") {
		t.Fatalf("a non-zero exit is a normal result: %+v", r)
	}
	r = e.call("exec", map[string]any{"sandbox": "box", "command": "echo hi", "timeout_seconds": 10})
	if r.isError || r.data["stdout"] != "hi\n" || !strings.Contains(r.text, "--- stdout ---\nhi") {
		t.Fatalf("exec = %+v", r)
	}
	if r := e.call("exec", map[string]any{"sandbox": "box", "command": "stderr warn"}); !strings.Contains(r.text, "--- stderr ---\nwarn") {
		t.Fatalf("stderr render = %q", r.text)
	}
	if r := e.call("exec", map[string]any{"sandbox": "box", "command": "exit 0"}); !strings.Contains(r.text, "(no output)") {
		t.Fatalf("empty render = %q", r.text)
	}
	if r := e.call("exec", map[string]any{"sandbox": "box", "command": "sleep", "timeout_seconds": 1}); r.isError || r.data["timed_out"] != true || r.data["exit_code"] != float64(124) {
		t.Fatalf("timeout = %+v", r)
	}
	if r := e.call("exec", map[string]any{"sandbox": "box", "command": "x", "timeout_seconds": -1}); !r.isError {
		t.Fatal("negative timeout")
	}
	// An API failure is a tool error with a next step.
	r = e.call("exec", map[string]any{"sandbox": "gone", "command": "echo"})
	if !r.isError || !strings.Contains(r.text, `sandbox "gone" not found`) || !strings.Contains(r.text, "Next: it may have been destroyed by its idle lifecycle; call sandbox_list or sandbox_create") {
		t.Fatalf("missing sandbox = %+v", r)
	}
	if r := e.call("exec", map[string]any{"sandbox": "", "command": "echo"}); !r.isError || !strings.Contains(r.text, "sandbox is required") {
		t.Fatalf("blank sandbox = %+v", r)
	}

	if r := e.call("write_file", map[string]any{"sandbox": "box", "path": "/w/a.txt", "content": "one\ntwo\n"}); r.isError || r.data["bytes"] != float64(8) {
		t.Fatalf("write = %+v", r)
	}
	if r := e.call("read_file", map[string]any{"sandbox": "box", "path": "/w/a.txt", "offset_line": 2}); r.isError || r.data["content"] != "two\n" || !strings.HasPrefix(r.text, "/w/a.txt (lines 2-2)") {
		t.Fatalf("read = %+v", r)
	}
	e.fake.PutFile(box.ID, "/w/long.txt", []byte(strings.Repeat("x\n", 3000)))
	if r := e.call("read_file", map[string]any{"sandbox": "box", "path": "/w/long.txt"}); !strings.Contains(r.text, "more from offset_line=2001") {
		t.Fatalf("read window header = %q", r.text[:80])
	}
	if r := e.call("edit_file", map[string]any{"sandbox": "box", "path": "/w/a.txt", "old_string": "two", "new_string": "2"}); r.isError {
		t.Fatal(r.text)
	}
	if got, _ := e.fake.File(box.ID, "/w/a.txt"); string(got) != "one\n2\n" {
		t.Fatalf("edited = %q", got)
	}
	if r := e.call("edit_file", map[string]any{"sandbox": "box", "path": "/w/a.txt", "old_string": "zzz", "new_string": "y"}); !r.isError || !strings.Contains(r.text, "edit_conflict") {
		t.Fatalf("edit miss = %+v", r)
	}
	if r := e.call("list_files", map[string]any{"sandbox": "box", "path": "/w"}); r.isError || len(r.data["entries"].([]any)) != 2 {
		t.Fatalf("list_files = %+v", r)
	}
	if r := e.call("search_files", map[string]any{"sandbox": "box", "path": "/w", "pattern": "*.txt"}); r.isError || len(r.data["files"].([]any)) != 2 {
		t.Fatalf("search = %+v", r)
	}
	if r := e.call("grep_files", map[string]any{"sandbox": "box", "path": "/w", "pattern": "one"}); r.isError || len(r.data["matches"].([]any)) != 1 {
		t.Fatalf("grep = %+v", r)
	}
	if r := e.call("expose_port", map[string]any{"sandbox": "box", "port": 3000}); r.isError || !strings.HasPrefix(r.text, "https://3000-") {
		t.Fatalf("expose = %+v", r)
	}
	if r := e.call("expose_port", map[string]any{"sandbox": "box", "port": 0}); !r.isError {
		t.Fatal("port 0")
	}

	p := e.call("start_process", map[string]any{"sandbox": "box", "command": "npm run dev"})
	sid, _ := p.data["session_id"].(string)
	if p.isError || sid == "" {
		t.Fatalf("start_process = %+v", p)
	}
	if r := e.call("process_logs", map[string]any{"sandbox": "box", "session_id": sid}); r.isError || !strings.Contains(r.text, "status: running") || !strings.Contains(r.text, "started npm run dev") {
		t.Fatalf("process_logs = %+v", r)
	}
	if r := e.call("stop_process", map[string]any{"sandbox": "box", "session_id": sid}); r.isError || r.data["stopped"] != true {
		t.Fatalf("stop = %+v", r)
	}
}

// TestIsolateIsRefused pins D11: no toolbox call reaches an isolate sandbox.
func TestIsolateIsRefused(t *testing.T) {
	e := newEnv(t, Options{Toolsets: []string{"all"}})
	e.fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
	args := map[string]map[string]any{
		"exec":          {"command": "x"},
		"read_file":     {"path": "/x"},
		"write_file":    {"path": "/x", "content": ""},
		"list_files":    {"path": "/x"},
		"edit_file":     {"path": "/x", "old_string": "a", "new_string": "b"},
		"search_files":  {"pattern": "p"},
		"grep_files":    {"pattern": "p"},
		"start_process": {"command": "x"},
		"process_logs":  {"session_id": "s"},
		"stop_process":  {"session_id": "s"},
	}
	for tool, a := range args {
		a["sandbox"] = "iso"
		r := e.call(tool, a)
		if !r.isError || !strings.Contains(r.text, "isolate sandboxes have no shell or filesystem") {
			t.Fatalf("%s on isolate = %+v", tool, r)
		}
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		for _, req := range s.Requests {
			if strings.Contains(req, "/toolbox/") || strings.Contains(req, "/sessions") {
				t.Fatalf("isolate guard leaked a request: %s", req)
			}
		}
	})
}

// TestPinnedLazyCreateSingleFlight pins §5.3: the pinned sandbox is created
// on the first call, once, even when first calls race; a failed create is
// not latched.
func TestPinnedLazyCreateSingleFlight(t *testing.T) {
	fake := agenttoolstest.New(t)
	fake.CreateDelay = 50 * time.Millisecond
	e := connect(t, fake, Options{Sandbox: "my-agent", CreateIfMissing: true, Image: "python:3.12"})
	if fake.Count() != 0 {
		t.Fatal("the pinned sandbox must not be created at startup")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := e.call("exec", map[string]any{"command": "echo hi"}); r.isError {
				t.Errorf("concurrent first call: %s", r.text)
			}
		}()
	}
	wg.Wait()
	fake.Observe(func(s *agenttoolstest.Server) {
		if s.CreatePosts != 1 || s.LastCreate.Image != "python:3.12" || s.LastCreate.Name != "my-agent" {
			t.Fatalf("POSTs = %d (%+v), want exactly 1", s.CreatePosts, s.LastCreate)
		}
	})

	failing := agenttoolstest.New(t)
	failing.FailCreates = 1
	e2 := connect(t, failing, Options{Sandbox: "my-agent", CreateIfMissing: true})
	if r := e2.call("exec", map[string]any{"command": "echo"}); !r.isError {
		t.Fatal("the first create was set to fail")
	}
	if r := e2.call("exec", map[string]any{"command": "echo"}); r.isError {
		t.Fatalf("a failed create must not be latched: %s", r.text)
	}
}

// TestPinnedRecreateNotice pins D6.
func TestPinnedRecreateNotice(t *testing.T) {
	e := newEnv(t, Options{Sandbox: "my-agent", CreateIfMissing: true})
	first := e.call("exec", map[string]any{"command": "echo hi"})
	if first.isError || first.data["sandbox_recreated"] != nil || first.data["notice"] != nil {
		t.Fatalf("first call = %+v", first)
	}
	sb := e.server.pinID
	e.fake.Remove(sb) // destroyed by its idle lifecycle
	second := e.call("exec", map[string]any{"command": "echo hi"})
	if second.isError || second.data["sandbox_recreated"] != true || !strings.HasPrefix(second.text, "NOTICE: the pinned sandbox no longer existed") {
		t.Fatalf("recreate call = %+v", second)
	}
	third := e.call("exec", map[string]any{"command": "echo hi"})
	if third.data["sandbox_recreated"] != nil || strings.Contains(third.text, "NOTICE") {
		t.Fatalf("the notice must appear exactly once: %+v", third)
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		if s.CreatePosts != 2 {
			t.Fatalf("creates = %d, want 2", s.CreatePosts)
		}
	})
}

func TestPinnedWithoutCreate(t *testing.T) {
	e := newEnv(t, Options{Sandbox: "box"})
	r := e.call("read_file", map[string]any{"path": "/x"})
	if !r.isError || !strings.Contains(r.text, `the pinned sandbox "box" does not exist`) || !strings.Contains(r.text, "--create-if-missing") {
		t.Fatalf("missing pinned = %+v", r)
	}
	e.fake.AddSandbox(models.Sandbox{Name: "box"})
	if r := e.call("write_file", map[string]any{"path": "/a", "content": "x"}); r.isError {
		t.Fatal(r.text)
	}
	// An existing pinned sandbox found by name later isn't "recreated".
	if r := e.call("list_files", map[string]any{"path": "/"}); r.isError || r.data["sandbox_recreated"] != nil {
		t.Fatalf("list = %+v", r)
	}
}

// TestPinnedStoppedSandboxStartsOnce pins D7.
func TestPinnedStoppedSandboxStartsOnce(t *testing.T) {
	e := newEnv(t, Options{Sandbox: "box"})
	e.fake.AddSandbox(models.Sandbox{Name: "box", Status: models.SandboxStatusStopped})
	if r := e.call("exec", map[string]any{"command": "echo up"}); r.isError || r.data["stdout"] != "up\n" {
		t.Fatalf("exec on stopped = %+v", r)
	}
	if r := e.call("exec", map[string]any{"command": "echo up"}); r.isError {
		t.Fatal(r.text)
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		if s.StartCalls != 1 {
			t.Fatalf("Start calls = %d, want 1", s.StartCalls)
		}
	})
	// expose_port doesn't need the toolbox, so it doesn't start anything.
	if r := e.call("expose_port", map[string]any{"port": 8080}); r.isError {
		t.Fatal(r.text)
	}
}

// TestRemoteNotices pins RR2 and the remote exec channel.
func TestRemoteNotices(t *testing.T) {
	e := newEnv(t, Options{Sandbox: "my-agent", CreateIfMissing: true, Remote: true})
	r := e.call("exec", map[string]any{"command": "echo hi"})
	if r.isError || r.data["sandbox_created"] != true || !strings.Contains(r.text, "NOTICE: this is a newly created sandbox") {
		t.Fatalf("remote lazy create = %+v", r)
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		if s.StreamDials != 0 || s.BufferedExecs != 1 {
			t.Fatalf("remote exec must be buffered: dials %d buffered %d", s.StreamDials, s.BufferedExecs)
		}
	})
	// A fresh stateless request on the existing sandbox: no flag.
	e2 := connect(t, e.fake, Options{Sandbox: "my-agent", CreateIfMissing: true, Remote: true})
	if r := e2.call("exec", map[string]any{"command": "echo hi"}); r.isError || r.data["sandbox_created"] != nil {
		t.Fatalf("existing sandbox = %+v", r)
	}
}

// TestEphemeralShutdown pins §5.3: --ephemeral destroys the pinned sandbox
// exactly once on clean shutdown, and only if it was used.
func TestEphemeralShutdown(t *testing.T) {
	e := newEnv(t, Options{Sandbox: "box", CreateIfMissing: true, Ephemeral: true})
	if err := e.server.Shutdown(context.Background()); err != nil || e.fake.Count() != 0 {
		t.Fatalf("unused ephemeral shutdown = %v", err)
	}
	e = newEnv(t, Options{Sandbox: "box", CreateIfMissing: true, Ephemeral: true})
	if r := e.call("exec", map[string]any{"command": "echo"}); r.isError {
		t.Fatal(r.text)
	}
	for i := 0; i < 2; i++ {
		if err := e.server.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	e.fake.Observe(func(s *agenttoolstest.Server) {
		if s.DestroyCalls != 1 {
			t.Fatalf("destroys = %d, want exactly 1", s.DestroyCalls)
		}
	})
	// Not ephemeral: shutdown leaves the sandbox.
	e = newEnv(t, Options{Sandbox: "box", CreateIfMissing: true})
	e.call("exec", map[string]any{"command": "echo"})
	if err := e.server.Shutdown(context.Background()); err != nil || e.fake.Count() != 1 {
		t.Fatal("non-ephemeral shutdown must keep the sandbox")
	}
}

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name  string
		opts  Options
		param string
	}{
		{name: "defaults", opts: Options{}},
		{name: "all toolsets", opts: Options{Toolsets: []string{"all", "core"}}},
		{name: "blank toolsets", opts: Options{Toolsets: []string{" "}}},
		{name: "unknown toolset", opts: Options{Toolsets: []string{"code"}}, param: "toolsets"},
		{name: "remote needs sandbox", opts: Options{Remote: true}, param: "sandbox"},
		{name: "create needs sandbox", opts: Options{CreateIfMissing: true}, param: "create_if_missing"},
		{name: "create needs a valid name", opts: Options{Sandbox: "sb-0123456789abcdef", CreateIfMissing: true}, param: "sandbox"},
		{name: "image needs create", opts: Options{Sandbox: "x", Image: "alpine"}, param: "image"},
		{name: "runtime needs create", opts: Options{Sandbox: "x", Runtime: "docker"}, param: "runtime"},
		{name: "isolate runtime", opts: Options{Sandbox: "x", CreateIfMissing: true, Runtime: "isolate"}, param: "runtime"},
		{name: "ephemeral needs sandbox", opts: Options{Ephemeral: true}, param: "ephemeral"},
		{name: "ephemeral not remote", opts: Options{Sandbox: "x", Ephemeral: true, Remote: true}, param: "ephemeral"},
		{name: "negative cap", opts: Options{MaxCreates: -1}, param: "max_creates"},
		{name: "negative output", opts: Options{MaxOutputBytes: -1}, param: "max_output_bytes"},
		{name: "negative idle", opts: Options{StopIfIdle: -time.Second}, param: "stop_if_idle"},
		{name: "idle too long", opts: Options{DestroyIfIdle: 31 * 24 * time.Hour}, param: "destroy_if_idle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.opts
			err := o.Validate()
			if tt.param == "" {
				if err != nil {
					t.Fatalf("Validate = %v", err)
				}
				return
			}
			oe, ok := err.(*OptionError)
			if !ok || oe.Param != tt.param {
				t.Fatalf("Validate = %v, want an error naming %s", err, tt.param)
			}
			if !strings.HasPrefix(oe.Flag(), "--") || strings.Contains(oe.Flag(), "_") || oe.Error() == "" {
				t.Fatalf("flag spelling %q", oe.Flag())
			}
		})
	}
	o := Options{Toolsets: ParseToolsets("files, process,,")}
	if err := o.Validate(); err != nil || strings.Join(o.Toolsets, ",") != "files,process" {
		t.Fatalf("ParseToolsets = %v, %v", o.Toolsets, err)
	}
	if _, err := New(nil, Options{Toolsets: []string{"nope"}}, "x"); err == nil {
		t.Fatal("New must validate")
	}
}

func TestLifecycleOptions(t *testing.T) {
	keep := (&Options{Keep: true}).lifecycle(0)
	if keep != nil {
		t.Fatalf("keep = %+v", keep)
	}
	keepWithDestroy := (&Options{Keep: true}).lifecycle(time.Hour)
	if keepWithDestroy.StopIfIdleFor != 0 || keepWithDestroy.DestroyIfIdleFor != time.Hour {
		t.Fatalf("keep + destroy = %+v", keepWithDestroy)
	}
	custom := (&Options{StopIfIdle: time.Minute, DestroyIfIdle: 2 * time.Hour}).lifecycle(0)
	if custom.StopIfIdleFor != time.Minute || custom.DestroyIfIdleFor != 2*time.Hour {
		t.Fatalf("custom = %+v", custom)
	}
}

func TestInstructions(t *testing.T) {
	if s := newEnv(t, Options{Sandbox: "box", CreateIfMissing: true}).server.instructions(); !strings.Contains(s, `"box"`) || !strings.Contains(s, "created on the first call") {
		t.Fatalf("pinned instructions = %q", s)
	}
	if s := newEnv(t, Options{}).server.instructions(); !strings.Contains(s, "sandbox_create") {
		t.Fatalf("unpinned instructions = %q", s)
	}
}
