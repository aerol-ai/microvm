package agentmcp

import (
	"context"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

// These calls take the error and formatting branches the happy-path MCP
// tests leave alone: a failed create, a server that ignores the page limit,
// exec text that has a signal and no trailing newline, a dropped exec
// stream (retryable), a pinned sandbox that has to be recreated, an isolate
// with no shell, a start that fails, and a background command that has
// already exited.
func TestToolErrorAndFormatBranches(t *testing.T) {
	failed := agenttoolstest.New(t)
	failed.FailCreates = 1
	if r := connect(t, failed, Options{Toolsets: []string{"all"}}).call("sandbox_create", map[string]any{"image": "alpine"}); !r.isError {
		t.Fatalf("create failure was not an error: %+v", r)
	}

	wide := agenttoolstest.New(t)
	wide.IgnoreLimit = true
	for i := 0; i < listPageSize+1; i++ {
		wide.AddSandbox(models.Sandbox{Name: "s"})
	}
	listed := connect(t, wide, Options{Toolsets: []string{"all"}}).call("sandbox_list", map[string]any{})
	rows, _ := listed.data["sandboxes"].([]any)
	if listed.isError || len(rows) != listPageSize {
		t.Fatalf("list trim = err %v rows %d", listed.isError, len(rows))
	}

	fake := agenttoolstest.New(t)
	fake.AddSandbox(models.Sandbox{Name: "box"})
	fake.ExecFunc = func(_ string, _ io.Reader, out func(stream byte, b []byte), _ <-chan struct{}) (int, string) {
		out(1, []byte("hi"))
		out(2, []byte("err"))
		return 1, "TERM"
	}
	e := connect(t, fake, Options{Toolsets: []string{"all"}})
	r := e.call("exec", map[string]any{"sandbox": "box", "command": "boom"})
	if r.isError || !strings.Contains(r.text, "(signal TERM)") || !strings.Contains(r.text, "hi\n") || !strings.Contains(r.text, "err\n") {
		t.Fatalf("formatted exec = err %v %q", r.isError, r.text)
	}

	fake.ExecFunc = func(_ string, _ io.Reader, _ func(stream byte, b []byte), _ <-chan struct{}) (int, string) {
		return 0, agenttoolstest.DropStream
	}
	dropped := e.call("exec", map[string]any{"sandbox": "box", "command": "drop"})
	if !dropped.isError || !strings.Contains(dropped.text, "retryable") {
		t.Fatalf("dropped exec = err %v %q", dropped.isError, dropped.text)
	}

	pin := agenttoolstest.New(t)
	sb := pin.AddSandbox(models.Sandbox{Name: "pin"})
	pe := connect(t, pin, Options{Sandbox: "pin", CreateIfMissing: true, Toolsets: []string{"all"}})
	if r := pe.call("exec", map[string]any{"command": "echo hi"}); r.isError {
		t.Fatalf("pinned exec: %s", r.text)
	}
	// The cached id is gone, but the name still resolves. That is the
	// "recreated underneath us" path, as opposed to creating a new one.
	pin.Remove(sb.ID)
	pin.AddSandbox(models.Sandbox{Name: "pin"})
	recreated := pe.call("exec", map[string]any{"command": "echo hi"})
	if recreated.isError || !strings.Contains(recreated.text, "no longer existed") {
		t.Fatalf("recreate = err %v %q", recreated.isError, recreated.text)
	}

	iso := agenttoolstest.New(t)
	iso.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
	if r := connect(t, iso, Options{Sandbox: "iso", Toolsets: []string{"all"}}).call("exec", map[string]any{"command": "echo"}); !r.isError || !strings.Contains(r.text, "isolate") {
		t.Fatalf("isolate exec = err %v %q", r.isError, r.text)
	}

	stopped := agenttoolstest.New(t)
	stopped.AddSandbox(models.Sandbox{Name: "stopped", Status: models.SandboxStatusStopped})
	stopped.FailStart = true
	if r := connect(t, stopped, Options{Sandbox: "stopped", Toolsets: []string{"all"}}).call("exec", map[string]any{"command": "echo"}); !r.isError || !strings.Contains(r.text, "start") {
		t.Fatalf("failed start = err %v %q", r.isError, r.text)
	}

	procs := agenttoolstest.New(t)
	procs.AddSandbox(models.Sandbox{Name: "box"})
	pe2 := connect(t, procs, Options{Toolsets: []string{"all"}})
	started := pe2.call("start_process", map[string]any{"sandbox": "box", "command": "exit 3"})
	sid, _ := started.data["session_id"].(string)
	logs := pe2.call("process_logs", map[string]any{"sandbox": "box", "session_id": sid})
	if started.isError || logs.isError || !strings.Contains(logs.text, "exit_code 3") {
		t.Fatalf("logs = start %v %q logs %v %q", started.isError, started.text, logs.isError, logs.text)
	}

	for _, call := range []struct {
		name string
		args map[string]any
	}{
		{"write_file", map[string]any{"sandbox": "missing", "path": "/a", "content": "x"}},
		{"list_files", map[string]any{"sandbox": "missing"}},
		{"search_files", map[string]any{"sandbox": "missing", "pattern": "*.go"}},
		{"grep_files", map[string]any{"sandbox": "missing", "pattern": "x"}},
		{"expose_port", map[string]any{"sandbox": "missing", "port": 9}},
		{"stop_process", map[string]any{"sandbox": "missing", "session_id": "ses"}},
	} {
		if r := pe2.call(call.name, call.args); !r.isError {
			t.Fatalf("%s missing sandbox was not an error", call.name)
		}
	}

	if asJSON(math.NaN()) == "" {
		t.Fatal("NaN JSON fallback was empty")
	}

	down := agenttoolstest.New(t)
	down.Close()
	if _, _, err := connect(t, down, Options{Toolsets: []string{"all"}}).server.sandboxList(t.Context(), listIn{}); err == nil {
		t.Fatal("list against a closed server succeeded")
	}
	if _, _, err := connect(t, down, Options{Toolsets: []string{"all"}}).server.sandboxDestroy(t.Context(), destroyIn{Sandbox: "gone"}); err == nil {
		t.Fatal("destroy against a closed server succeeded")
	}

	broken := agenttoolstest.New(t)
	broken.AddSandbox(models.Sandbox{Name: "box", Status: models.SandboxStatusStarted})
	broken.FailToolbox = true
	broken.FailSessions = true
	broken.FailExpose = true
	broken.FailDestroy = true
	be := connect(t, broken, Options{Toolsets: []string{"all"}})
	for _, call := range []struct {
		name string
		args map[string]any
	}{
		{"write_file", map[string]any{"sandbox": "box", "path": "/a", "content": "x"}},
		{"list_files", map[string]any{"sandbox": "box"}},
		{"search_files", map[string]any{"sandbox": "box", "pattern": "*.go"}},
		{"grep_files", map[string]any{"sandbox": "box", "pattern": "x"}},
		{"edit_file", map[string]any{"sandbox": "box", "path": "/a", "old_string": "a", "new_string": "b"}},
		{"expose_port", map[string]any{"sandbox": "box", "port": 9}},
		{"start_process", map[string]any{"sandbox": "box", "command": "sleep 1"}},
		{"process_logs", map[string]any{"sandbox": "box", "session_id": "ses"}},
		{"stop_process", map[string]any{"sandbox": "box", "session_id": "ses"}},
		{"sandbox_destroy", map[string]any{"sandbox": "box"}},
	} {
		if r := be.call(call.name, call.args); !r.isError {
			t.Fatalf("%s against a failing server was not an error", call.name)
		}
	}
}

func TestCoverage97EphemeralShutdownDestroyFails(t *testing.T) {
	fake := agenttoolstest.New(t)
	box := fake.AddSandbox(models.Sandbox{Name: "box"})
	fake.FailDestroy = true
	env := connect(t, fake, Options{})
	env.server.opts.Ephemeral = true
	env.server.pinID = box.ID
	if err := env.server.Shutdown(context.Background()); err == nil {
		t.Fatal("ephemeral shutdown ignored a destroy failure")
	}
}
