package agenttools

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

func newTestTools(t *testing.T, source Source) (*Tools, *agenttoolstest.Server, *[]string) {
	t.Helper()
	fake := agenttoolstest.New(t)
	var warnings []string
	tools, err := New(Config{APIURL: fake.URL, Token: agenttoolstest.Token, Source: source, Warn: func(s string) { warnings = append(warnings, s) }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return tools, fake, &warnings
}

func requestsMatching(fake *agenttoolstest.Server, prefix string) []string {
	var out []string
	fake.Observe(func(s *agenttoolstest.Server) {
		for _, r := range s.Requests {
			if strings.HasPrefix(r, prefix) {
				out = append(out, r)
			}
		}
	})
	return out
}

func TestNewRequiresToken(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "")
	_, err := New(Config{APIURL: "http://127.0.0.1:1"})
	if !IsCode(err, CodeUnauthorized) {
		t.Fatalf("New without a token = %v, want unauthorized", err)
	}
	tools, err := New(Config{APIURL: "http://127.0.0.1:1", Token: "x"})
	if err != nil || tools.Source() != SourceCLI || tools.Client() == nil {
		t.Fatalf("defaults: %v %v", tools, err)
	}
}

// TestResolveRoutesByShape is the D12 router table: an ID-shaped ref is an
// ID lookup only, anything else is a name lookup only, one request each.
func TestResolveRoutesByShape(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	byID := fake.AddSandbox(models.Sandbox{ID: "sb-00000000000000aa", Name: "named"})
	fake.AddSandbox(models.Sandbox{ID: "sb-00000000000000bb", Name: "sb-build"})

	sb, err := tools.Resolve(ctx, " sb-00000000000000aa ")
	if err != nil || sb.ID != byID.ID {
		t.Fatalf("Resolve(id) = (%v, %v)", sb, err)
	}
	if got := requestsMatching(fake, "GET /v1/sandboxes"); len(got) != 1 || got[0] != "GET /v1/sandboxes/sb-00000000000000aa" {
		t.Fatalf("id lookup made %v", got)
	}
	sb, err = tools.Resolve(ctx, "sb-build")
	if err != nil || sb.ID != "sb-00000000000000bb" {
		t.Fatalf("Resolve(name with sb- prefix) = (%v, %v)", sb, err)
	}
	if _, err := tools.Resolve(ctx, "sb-00000000000000cc"); !IsCode(err, CodeNotFound) || !strings.Contains(err.Error(), "sb-00000000000000cc") {
		t.Fatalf("missing id error = %v", err)
	}
	if _, err := tools.Resolve(ctx, "nope"); !IsCode(err, CodeNotFound) || !strings.Contains(err.Error(), `"nope"`) {
		t.Fatalf("missing name error = %v", err)
	}
	if _, err := tools.Resolve(ctx, "  "); !IsCode(err, CodeInvalidArgument) {
		t.Fatalf("blank ref error = %v", err)
	}
	ids := requestsMatching(fake, "GET /v1/sandboxes/")
	if len(ids) != 2 {
		t.Fatalf("name refs must never fall back to an ID lookup; ID requests: %v", ids)
	}
}

// TestResolveRefusesOldServer is CEO review CF5: a server that predates
// ?name= ignores it and returns an ordinary list; the reply must not be
// used, and nothing may be sent to whatever sandbox it happens to list.
func TestResolveRefusesOldServer(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	for _, name := range []string{"a", "b", "c"} {
		fake.AddSandbox(models.Sandbox{Name: name})
	}
	fake.IgnoreNameFilter = true
	if _, err := tools.Resolve(ctx, "b"); !IsCode(err, CodeServerUnsupported) {
		t.Fatalf("three rows for ?name= = %v, want server_unsupported", err)
	}
	if _, err := tools.Target(ctx, "b"); !IsCode(err, CodeServerUnsupported) {
		t.Fatalf("Target on an old server = %v", err)
	}
	fake.Remove("sb-0000000000000001")
	fake.Remove("sb-0000000000000003")
	// One row, but not the requested name.
	if _, err := tools.Resolve(ctx, "zzz"); !IsCode(err, CodeServerUnsupported) {
		t.Fatalf("one mismatched row = %v, want server_unsupported", err)
	}
	if n := len(requestsMatching(fake, "POST")) + len(requestsMatching(fake, "DELETE")); n != 0 {
		t.Fatalf("a follow-up request was sent after an untrustworthy lookup (%d)", n)
	}
}

func TestTargetGuardsAndStarts(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
	stopped := fake.AddSandbox(models.Sandbox{Name: "sleepy", Status: models.SandboxStatusStopped})
	fake.AddSandbox(models.Sandbox{Name: "awake"})

	_, err := tools.Target(ctx, "iso")
	if !IsCode(err, CodeUnsupportedRuntime) || !strings.Contains(err.Error(), "no shell or filesystem") {
		t.Fatalf("isolate target = %v", err)
	}
	if got := requestsMatching(fake, "GET /v1/sandboxes/"); len(got) != 0 {
		t.Fatalf("isolate guard must not reach the toolbox: %v", got)
	}
	sb, err := tools.Target(ctx, "sleepy")
	if err != nil || sb.Status != models.SandboxStatusStarted {
		t.Fatalf("stopped target = (%v, %v)", sb, err)
	}
	if _, err := tools.Target(ctx, "awake"); err != nil {
		t.Fatalf("started target: %v", err)
	}
	fake.Observe(func(s *agenttoolstest.Server) {
		if s.StartCalls != 1 {
			t.Fatalf("Start calls = %d, want exactly 1 (only the stopped sandbox)", s.StartCalls)
		}
	})
	fake.SetStatus(stopped.ID, models.SandboxStatusStopped)
	fake.FailStart = true
	if _, err := tools.Target(ctx, "sleepy"); !IsCode(err, CodeInternal) {
		t.Fatalf("failed start = %v", err)
	}
	if sb, err := tools.EnsureStarted(ctx, nil); sb != nil || err != nil {
		t.Fatal("EnsureStarted(nil) must be a no-op")
	}
	if _, err := tools.Target(ctx, "missing"); !IsCode(err, CodeNotFound) {
		t.Fatalf("missing target = %v", err)
	}
}

func TestGetOrCreate(t *testing.T) {
	ctx := context.Background()

	t.Run("creates with provenance tag", func(t *testing.T) {
		tools, fake, _ := newTestTools(t, SourceMCP)
		res, err := tools.GetOrCreate(ctx, CreateSpec{Name: "agent", Image: "alpine", Tags: map[string]string{"team": "x"}, Lifecycle: DefaultMCPLifecycle(), BlockNetwork: true, CPU: 1, MemoryMB: 512, Runtime: "docker", Env: map[string]string{"A": "1"}})
		if err != nil || !res.Created || res.Sandbox.Name != "agent" {
			t.Fatalf("GetOrCreate = (%+v, %v)", res, err)
		}
		fake.Observe(func(s *agenttoolstest.Server) {
			if s.LastCreate.Tags[CreatedByTag] != "mcp" || s.LastCreate.Tags["team"] != "x" {
				t.Fatalf("create tags = %v", s.LastCreate.Tags)
			}
			if s.LastCreate.Lifecycle == nil || s.LastCreate.Lifecycle.StopIfIdleFor.Minutes() != 30 || s.LastCreate.Lifecycle.DestroyIfIdleFor.Hours() != 24 {
				t.Fatalf("lifecycle = %+v", s.LastCreate.Lifecycle)
			}
			if !s.LastCreate.NetworkBlockAll || s.LastCreate.Env["A"] != "1" {
				t.Fatalf("create request = %+v", s.LastCreate)
			}
		})
	})

	t.Run("user value for the provenance tag wins", func(t *testing.T) {
		tools, fake, _ := newTestTools(t, SourceCLI)
		if _, err := tools.GetOrCreate(ctx, CreateSpec{Name: "agent", Image: "alpine", Tags: map[string]string{CreatedByTag: "ci"}}); err != nil {
			t.Fatal(err)
		}
		fake.Observe(func(s *agenttoolstest.Server) {
			if s.LastCreate.Tags[CreatedByTag] != "ci" {
				t.Fatalf("tag = %q, want the caller's value", s.LastCreate.Tags[CreatedByTag])
			}
		})
	})

	t.Run("existing name is returned and differences are warned", func(t *testing.T) {
		tools, fake, warnings := newTestTools(t, SourceCLI)
		existing := fake.AddSandbox(models.Sandbox{Name: "agent", Image: "ubuntu", Runtime: "docker"})
		res, err := tools.GetOrCreate(ctx, CreateSpec{Name: "agent", Image: "alpine", Runtime: "gvisor"})
		if err != nil || res.Created || res.Sandbox.ID != existing.ID {
			t.Fatalf("GetOrCreate = (%+v, %v)", res, err)
		}
		if len(*warnings) != 2 {
			t.Fatalf("warnings = %q, want image and runtime notices", *warnings)
		}
		fake.Observe(func(s *agenttoolstest.Server) {
			if s.CreatePosts != 0 {
				t.Fatal("an existing name must not POST")
			}
		})
	})

	t.Run("auto-name is generated once before the first attempt", func(t *testing.T) {
		tools, fake, _ := newTestTools(t, SourceCLI)
		calls := 0
		tools.newName = func() (string, error) { calls++; return "agent-abcdefghijkl", nil }
		fake.DropAfterCreate = 1
		res, err := tools.GetOrCreate(ctx, CreateSpec{Image: "alpine"})
		if err != nil || res.Sandbox.Name != "agent-abcdefghijkl" || calls != 1 {
			t.Fatalf("GetOrCreate = (%+v, %v), name generated %d times", res, err, calls)
		}
	})

	t.Run("real auto-names have the agent shape", func(t *testing.T) {
		name, err := autoName()
		if err != nil || !strings.HasPrefix(name, "agent-") || len(name) != len("agent-")+12 || models.ValidateSandboxName(name) != nil {
			t.Fatalf("autoName = %q, %v", name, err)
		}
		other, _ := autoName()
		if other == name {
			t.Fatal("two auto-names collided")
		}
	})

	t.Run("reserved names are rejected before any request", func(t *testing.T) {
		tools, fake, _ := newTestTools(t, SourceCLI)
		for _, name := range []string{"owner:x/y", "sb-0123456789abcdef"} {
			if _, err := tools.GetOrCreate(ctx, CreateSpec{Name: name, Image: "alpine"}); !IsCode(err, CodeInvalidArgument) {
				t.Fatalf("GetOrCreate(%q) = %v, want invalid_argument", name, err)
			}
		}
		if n := len(requestsMatching(fake, "")); n != 0 {
			t.Fatalf("reserved names sent %d requests", n)
		}
	})

	t.Run("old server refuses instead of creating", func(t *testing.T) {
		tools, fake, _ := newTestTools(t, SourceCLI)
		fake.AddSandbox(models.Sandbox{Name: "x"})
		fake.AddSandbox(models.Sandbox{Name: "y"})
		fake.IgnoreNameFilter = true
		if _, err := tools.GetOrCreate(ctx, CreateSpec{Name: "agent", Image: "alpine"}); !IsCode(err, CodeServerUnsupported) {
			t.Fatalf("GetOrCreate on an old server = %v", err)
		}
		fake.Observe(func(s *agenttoolstest.Server) {
			if s.CreatePosts != 0 {
				t.Fatal("must not create without a trustworthy lookup")
			}
		})
	})

	t.Run("create errors surface", func(t *testing.T) {
		tools, _, _ := newTestTools(t, SourceCLI)
		tools.newName = func() (string, error) { return "", errors.New("entropy gone") }
		if _, err := tools.GetOrCreate(ctx, CreateSpec{Image: "alpine"}); !IsCode(err, CodeInternal) {
			t.Fatalf("name generation failure = %v", err)
		}
		tools2, fake2, _ := newTestTools(t, SourceCLI)
		fake2.Close()
		if _, err := tools2.GetOrCreate(ctx, CreateSpec{Name: "agent", Image: "alpine"}); !IsCode(err, CodeUnreachable) {
			t.Fatalf("unreachable server = %v", err)
		}
	})
}

// TestGetOrCreateLostReply is the D5 proof: the server creates the sandbox
// and then drops the connection before replying. The SDK retries the same
// POST (same name), gets 409, and get-or-create resolves the name: exactly
// one sandbox exists and its ID comes back.
func TestGetOrCreateLostReply(t *testing.T) {
	tools, fake, _ := newTestTools(t, SourceCLI)
	fake.DropAfterCreate = 1
	res, err := tools.GetOrCreate(context.Background(), CreateSpec{Name: "agent", Image: "alpine"})
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if fake.Count() != 1 {
		t.Fatalf("%d sandboxes exist, want exactly 1", fake.Count())
	}
	fake.Observe(func(s *agenttoolstest.Server) {
		if len(s.CreatedIDs) != 1 || res.Sandbox.ID != s.CreatedIDs[0] {
			t.Fatalf("returned %s, created %v", res.Sandbox.ID, s.CreatedIDs)
		}
		if s.CreatePosts != 2 {
			t.Fatalf("POSTs = %d, want 2 (the lost one and its retry)", s.CreatePosts)
		}
	})
	if res.Created {
		t.Fatal("a create resolved through 409 reports created=false")
	}
}

func TestGetOrCreateConflictOnSomethingElse(t *testing.T) {
	tools, fake, _ := newTestTools(t, SourceCLI)
	// The create 409s but the name never appears: report the create's own
	// conflict rather than looping or claiming a sandbox that isn't there.
	fake.ConflictAlways = true
	_, err := tools.GetOrCreate(context.Background(), CreateSpec{Name: "agent", Image: "alpine"})
	if !IsCode(err, CodeConflict) || !strings.Contains(err.Error(), "reservation conflict") {
		t.Fatalf("GetOrCreate = %v, want the create's conflict", err)
	}
	if fake.Count() != 0 {
		t.Fatal("nothing should exist")
	}
}
