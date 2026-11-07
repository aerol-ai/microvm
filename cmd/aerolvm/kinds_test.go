package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

// kindsNow is the clock every kinds golden is taken at: 34 days after the
// fake's sandboxes were made.
var kindsNow = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// fakeKinds serves the routes the new kinds read (/v1/snapshots, /v1/tokens,
// /v1/capacity, /v1/cluster/members) and hands everything else to the
// agenttoolstest fake, so sandboxes come from the same fake the old verbs
// use.
type fakeKinds struct {
	srv *httptest.Server

	mu        sync.Mutex
	snapshots map[string]map[string]any
	tokens    []map[string]any
	members   []map[string]any
	capacity  map[string]any
	pageCap   int            // the most snapshots or sandboxes one page holds
	status    map[string]int // "METHOD path" -> answer with this status
	sameToken bool           // every sandbox page says "more: same"
	queries   []string
}

func newKindsHarness(t *testing.T) (*harness, *fakeKinds) {
	t.Helper()
	h := newHarness(t)
	h.app.now = func() time.Time { return kindsNow }
	f := &fakeKinds{snapshots: map[string]map[string]any{}, status: map[string]int{}, pageCap: 2}
	target, _ := url.Parse(h.fake.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(r *http.Response) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.sameToken && r.Request.URL.Path == "/v1/sandboxes" {
			r.Header.Set("X-Cluster-List-Next-Page-Token", "same")
		}
		return nil
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.queries = append(f.queries, r.Method+" "+r.URL.RequestURI())
		status, cap := f.status[r.Method+" "+r.URL.Path], f.pageCap
		f.mu.Unlock()
		if status != 0 {
			writeFakeJSON(w, status, map[string]string{"error": http.StatusText(status)})
			return
		}
		if r.URL.Path == "/v1/sandboxes" && r.Method == http.MethodGet {
			// Small pages, so get pages through the fake's cursor.
			q := r.URL.Query()
			q.Set("limit", strconv.Itoa(cap))
			r.URL.RawQuery = q.Encode()
		}
		if !f.serve(w, r) {
			proxy.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	h.env["SB_API_URL"] = f.srv.URL
	return h, f
}

func (f *fakeKinds) serve(w http.ResponseWriter, r *http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+agenttoolstest.Token {
		return false
	}
	path := r.URL.Path
	switch {
	case path == "/v1/snapshots" && r.Method == http.MethodGet:
		names := make([]string, 0, len(f.snapshots))
		for n := range f.snapshots {
			names = append(names, n)
		}
		sort.Strings(names)
		after := r.URL.Query().Get("starting_after")
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		page := []map[string]any{}
		more := false
		for _, n := range names {
			if n <= after {
				continue
			}
			if len(page) == min(limit, f.pageCap) {
				more = true
				break
			}
			page = append(page, f.snapshots[n])
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"snapshots": page, "has_more": more})
	case strings.HasPrefix(path, "/v1/snapshots/"):
		name := strings.TrimPrefix(path, "/v1/snapshots/")
		snap, ok := f.snapshots[name]
		switch {
		case !ok:
			writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "snapshot not found"})
		case r.Method == http.MethodDelete:
			delete(f.snapshots, name)
			w.WriteHeader(http.StatusNoContent)
		default:
			writeFakeJSON(w, http.StatusOK, snap)
		}
	case path == "/v1/tokens" && r.Method == http.MethodGet:
		writeFakeJSON(w, http.StatusOK, map[string]any{"tokens": f.tokens})
	case strings.HasPrefix(path, "/v1/tokens/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/v1/tokens/")
		for i, tok := range f.tokens {
			if tok["id"] == id {
				f.tokens = append(f.tokens[:i], f.tokens[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return true
			}
		}
		writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "token not found"})
	case path == "/v1/cluster/members" && r.Method == http.MethodGet:
		writeFakeJSON(w, http.StatusOK, map[string]any{"members": f.members})
	case path == "/v1/capacity" && r.Method == http.MethodGet:
		writeFakeJSON(w, http.StatusOK, f.capacity)
	default:
		return false
	}
	return true
}

// kindsFixture fills the fakes: three sandboxes with tags, one with every
// field describe prints, two snapshots and three tokens (two share a name).
func kindsFixture(h *harness, f *fakeKinds) {
	exit := 3
	h.fake.AddSandbox(models.Sandbox{Name: "box", Image: "python:3.12", Runtime: "docker", CPU: 1.5, MemoryMB: 512,
		PublicURL: "https://box.example.com", Tags: map[string]string{"app": "web", "tier": "front"},
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: "http", PublicURL: "https://8080-box.example.com"}, {Port: 5432, Protocol: "tcp", HostPort: 22001}},
		Lifecycle:    models.Lifecycle{StopIfIdleFor: 30 * time.Minute, DestroyAtAge: 48 * time.Hour},
		LastActiveAt: kindsNow.Add(-90 * time.Second), NetworkAllowOut: []string{"pypi.org", "*.pythonhosted.org"},
		Engine: "containerd", StatusReason: "warm", ExitCode: &exit, LastError: "toolbox restarted once"})
	h.fake.AddSandbox(models.Sandbox{Name: "db", Image: "postgres:17", Runtime: "docker", Tags: map[string]string{"app": "db"},
		NetworkBlockAll: true, CreatedAt: kindsNow.Add(-5 * time.Hour)})
	h.fake.AddSandbox(models.Sandbox{Runtime: "wasm", Status: models.SandboxStatusStopped, Tags: map[string]string{"app": "web"},
		NetworkDenyOut: []string{"10.0.0.0/8"}, CreatedAt: kindsNow.Add(-45 * time.Second)})
	verified := kindsNow.Add(-time.Hour)
	f.snapshots["snap-a"] = map[string]any{"name": "snap-a", "image": "snapshots/snap-a", "source_sandbox_id": "sb-0000000000000001",
		"created_at": kindsNow.Add(-3 * 24 * time.Hour), "image_distribution_mode": "local", "image_id": "sha256:aaa",
		"image_digest": "sha256:ddd", "image_verified_at": verified, "entrypoint": []string{"python", "app.py"}}
	f.snapshots["snap-b"] = map[string]any{"name": "snap-b", "image": "registry.example/snap-b", "source_sandbox_id": "sb-0000000000000002",
		"created_at": kindsNow.Add(-400 * 24 * time.Hour), "image_distribution_mode": "external_registry", "image_registry_ref": "registry.example/snap-b:1"}
	f.snapshots["snap-c"] = map[string]any{"name": "snap-c", "image": "snapshots/snap-c", "source_sandbox_id": "", "created_at": time.Time{}}
	made := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	f.tokens = []map[string]any{
		{"id": "tok_aaaaaaaaaaaa", "name": "ci", "role": "runner", "team": "ml", "created_by": "operator", "created_at": made, "expires_at": made.Add(90 * 24 * time.Hour), "expired": false},
		{"id": "tok_bbbbbbbbbbbb", "name": "ci", "role": "viewer", "team": "web", "created_by": "", "created_at": made, "expires_at": made.Add(10 * 24 * time.Hour), "expired": true},
		{"id": "tok_cccccccccccc", "name": "deploy", "role": "admin", "team": "*", "created_by": "alice", "created_at": made, "expires_at": kindsNow.Add(-time.Hour), "expired": false},
	}
}

// kindsGolden runs args and checks the transcript against testdata/kinds.
func kindsGolden(t *testing.T, h *harness, f *fakeKinds, code int, golden string, args ...string) {
	t.Helper()
	got := h.run(args...)
	if got != code {
		t.Fatalf("%v = exit %d, want %d (stdout %q, stderr %q)", args, got, code, h.stdout.String(), h.stderr.String())
	}
	checkGoldenIn(t, "kinds", golden+".golden", strings.ReplaceAll(h.transcript(got), f.srv.URL, "URL"))
}

func TestGetSandboxesForms(t *testing.T) {
	h, f := newKindsHarness(t)
	kindsFixture(h, f)
	for _, tc := range []struct {
		golden string
		code   int
		args   []string
	}{
		{"get-sb", exitOK, []string{"get", "sb"}},
		{"get-sandboxes-wide", exitOK, []string{"get", "sandboxes", "-o", "wide"}},
		{"get-sb-name", exitOK, []string{"get", "sandbox", "-o", "name"}},
		{"get-sb-json-list", exitOK, []string{"get", "sb", "--json"}},
		{"get-sb-one-yaml", exitOK, []string{"get", "sb", "db", "-o", "yaml"}},
		{"get-sb-two-yaml", exitOK, []string{"get", "sb", "db", "sb-0000000000000003", "--output", "yaml"}},
		{"get-sb-selector", exitOK, []string{"get", "sb", "-l", "app=web"}},
		{"get-sb-selector-not", exitOK, []string{"get", "sb", "--selector", "app!=web"}},
		{"get-sb-selector-exists", exitOK, []string{"get", "sb", "-l", "tier", "-o", "name"}},
		{"get-sb-selector-absent", exitOK, []string{"get", "sb", "-l", "!tier,app==web", "-o", "name"}},
		{"get-sb-selector-none", exitOK, []string{"get", "sb", "-l", "app=nothing"}},
		{"get-sb-missing", exitError, []string{"get", "sb", "box", "ghost"}},
		{"get-sb-selector-set", exitUsage, []string{"get", "sb", "-l", "app in (a,b)"}},
		{"get-sb-selector-names", exitUsage, []string{"get", "sb", "box", "-l", "app=web"}},
		{"get-sb-bad-output", exitUsage, []string{"get", "sb", "-o", "jsonpath={.id}"}},
		{"get-old-form-selector", exitUsage, []string{"get", "box", "-l", "app=web"}},
	} {
		kindsGolden(t, h, f, tc.code, tc.golden, tc.args...)
	}
	// The selector's equality terms reach sandboxd as tag filters.
	f.mu.Lock()
	sawTag := false
	for _, q := range f.queries {
		if strings.Contains(q, "tag.app=nothing") {
			sawTag = true
		}
	}
	f.mu.Unlock()
	if !sawTag {
		t.Fatal("-l app=nothing never reached sandboxd as ?tag.app=nothing")
	}
}

// `get sb <name> --json` and `-o json` are the stable contract's shape:
// byte for byte what `get <name> --json` prints.
func TestGetSandboxJSONMatchesOldForm(t *testing.T) {
	h, f := newKindsHarness(t)
	kindsFixture(h, f)
	if code := h.run("get", "box", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	old := h.stdout.String()
	for _, args := range [][]string{{"get", "sb", "box", "--json"}, {"get", "sb", "box", "-o", "json"}, {"describe", "sb", "box", "-o", "json"}} {
		if code := h.run(args...); code != exitOK || h.stdout.String() != old {
			t.Fatalf("%v = %d\n%s\nwant\n%s", args, code, h.stdout.String(), old)
		}
	}
}

func TestGetSandboxesPagingAndEmpty(t *testing.T) {
	h, f := newKindsHarness(t)
	if code := h.run("get", "sb"); code != exitOK || h.stdout.String() != "" || !strings.Contains(h.stderr.String(), "no sandboxes") {
		t.Fatalf("empty = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run("get", "sb", "--json"); code != exitOK || strings.TrimSpace(h.stdout.String()) != "{\n  \"sandboxes\": []\n}" {
		t.Fatalf("empty json = %d %q", code, h.stdout.String())
	}
	for i := 0; i < 5; i++ {
		h.fake.AddSandbox(models.Sandbox{Name: fmt.Sprintf("p%d", i)})
	}
	// Pages of two: three calls, five rows.
	if code := h.run("get", "sb", "-o", "name"); code != exitOK || h.stdout.String() != "sandbox/p0\nsandbox/p1\nsandbox/p2\nsandbox/p3\nsandbox/p4\n" {
		t.Fatalf("paged = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	// A server whose cursor never moves must not loop forever.
	f.mu.Lock()
	f.sameToken = true
	f.mu.Unlock()
	if code := h.run("get", "sb", "-o", "name"); code != exitOK || strings.Count(h.stdout.String(), "sandbox/") != 4 {
		t.Fatalf("stuck cursor = %d %q", code, h.stdout.String())
	}
	f.mu.Lock()
	f.sameToken = false
	f.status["GET /v1/sandboxes"] = http.StatusInternalServerError
	f.mu.Unlock()
	if code := h.run("get", "sb", "--json"); code != exitError || h.errorEnvelope().HTTPStatus != 500 {
		t.Fatalf("list failure = %d %q", code, h.stderr.String())
	}
	delete(h.env, "SB_PAT_TOKEN")
	delete(h.env, "SB_API_URL")
	h.env["XDG_CONFIG_HOME"] = t.TempDir()
	for _, args := range [][]string{{"get", "sb"}, {"describe", "sb", "x"}, {"delete", "sb", "x"}, {"get", "snap"}, {"get", "tokens"}} {
		if code := h.run(args...); code != exitError || !strings.Contains(h.stderr.String(), "not logged in") {
			t.Fatalf("%v with no login = %d %q", args, code, h.stderr.String())
		}
	}
}

// A list prints in name order (then ID), whatever order the server sends:
// the live list route's order changes from call to call (lane 4 live run
// 1), and kubectl sorts by name.
func TestGetListsSortByName(t *testing.T) {
	h, f := newKindsHarness(t)
	// The fake answers in ID order, which is the reverse of name order here.
	for _, name := range []string{"zeta", "mid", "alpha"} {
		h.fake.AddSandbox(models.Sandbox{Name: name})
	}
	h.fake.AddSandbox(models.Sandbox{ID: "sb-00000000000000aa"})
	if code := h.run("get", "sb", "-o", "name"); code != exitOK ||
		h.stdout.String() != "sandbox/alpha\nsandbox/mid\nsandbox/sb-00000000000000aa\nsandbox/zeta\n" {
		t.Fatalf("get sb -o name = %d %q", code, h.stdout.String())
	}
	// Named sandboxes keep the order they were asked for.
	if code := h.run("get", "sb", "zeta", "alpha", "-o", "name"); code != exitOK || h.stdout.String() != "sandbox/zeta\nsandbox/alpha\n" {
		t.Fatalf("get sb zeta alpha = %d %q", code, h.stdout.String())
	}
	f.mu.Lock()
	f.tokens = []map[string]any{
		{"id": "tok_zzzzzzzzzzzz", "name": "b"}, {"id": "tok_yyyyyyyyyyyy", "name": "a"}, {"id": "tok_xxxxxxxxxxxx", "name": "b"},
	}
	f.mu.Unlock()
	if code := h.run("get", "tokens", "-o", "name"); code != exitOK ||
		h.stdout.String() != "token/tok_yyyyyyyyyyyy\ntoken/tok_xxxxxxxxxxxx\ntoken/tok_zzzzzzzzzzzz\n" {
		t.Fatalf("get tokens -o name = %d %q", code, h.stdout.String())
	}
}

func TestDescribeAndDeleteSandboxes(t *testing.T) {
	h, f := newKindsHarness(t)
	kindsFixture(h, f)
	for _, tc := range []struct {
		golden string
		code   int
		args   []string
	}{
		{"describe-sb", exitOK, []string{"describe", "sb", "box"}},
		{"describe-sb-plain", exitOK, []string{"describe", "sandbox", "db"}},
		{"describe-old-form", exitOK, []string{"describe", "sb-0000000000000003"}},
		{"describe-sb-yaml", exitOK, []string{"describe", "sb", "db", "-o", "yaml"}},
		{"describe-sb-missing", exitError, []string{"describe", "sb", "ghost"}},
		{"describe-sb-two", exitUsage, []string{"describe", "sb", "box", "db"}},
		{"describe-sb-wide", exitUsage, []string{"describe", "sb", "box", "-o", "wide"}},
		{"describe-selector", exitUsage, []string{"describe", "sb", "-l", "app=web"}},
		{"describe-old-form-selector", exitUsage, []string{"describe", "box", "-l", "app=web"}},
		{"delete-sb", exitOK, []string{"delete", "sb", "db"}},
		{"delete-sb-again", exitOK, []string{"delete", "sandboxes", "db"}},
		{"delete-sb-json", exitOK, []string{"delete", "sb", "box", "ghost", "--json"}},
		{"delete-sb-none", exitUsage, []string{"delete", "sb"}},
		{"delete-sb-force", exitUsage, []string{"delete", "sb", "box", "--force"}},
		{"delete-unknown-kind", exitUsage, []string{"delete", "nod", "wrk-1"}},
		{"delete-bad-flag", exitUsage, []string{"delete", "sb", "x", "--nope"}},
	} {
		kindsGolden(t, h, f, tc.code, tc.golden, tc.args...)
	}
	if h.fake.Count() != 1 {
		t.Fatalf("after deleting db and box, %d sandboxes are left, want 1", h.fake.Count())
	}
	// A failed destroy is reported, the rest still run, exit 1.
	h.fake.AddSandbox(models.Sandbox{Name: "keep"})
	h.fake.Observe(func(s *agenttoolstest.Server) { s.FailDestroy = true })
	if code := h.run("delete", "sb", "keep"); code != exitError || !strings.Contains(h.stderr.String(), "destroy failed") {
		t.Fatalf("failed delete = %d %q", code, h.stderr.String())
	}
}

func TestSnapshotKind(t *testing.T) {
	h, f := newKindsHarness(t)
	kindsFixture(h, f)
	for _, tc := range []struct {
		golden string
		code   int
		args   []string
	}{
		{"get-snapshots", exitOK, []string{"get", "snapshots"}},
		{"get-snap-wide", exitOK, []string{"get", "snap", "-o", "wide"}},
		{"get-snap-name", exitOK, []string{"get", "snapshot", "-o", "name"}},
		{"get-snap-one-json", exitOK, []string{"get", "snap", "snap-a", "-o", "json"}},
		{"get-snap-two-yaml", exitOK, []string{"get", "snap", "snap-a", "snap-b", "-o", "yaml"}},
		{"get-snap-missing", exitError, []string{"get", "snap", "ghost"}},
		{"get-snap-selector", exitUsage, []string{"get", "snap", "-l", "a=b"}},
		{"describe-snap", exitOK, []string{"describe", "snap", "snap-a"}},
		{"describe-snap-bare", exitOK, []string{"describe", "snapshot", "snap-c"}},
		{"describe-snap-json", exitOK, []string{"describe", "snapshots", "snap-b", "--json"}},
		{"describe-snap-missing", exitError, []string{"describe", "snap", "ghost", "--json"}},
		{"delete-snap", exitOK, []string{"delete", "snap", "snap-c"}},
		{"delete-snap-json", exitOK, []string{"delete", "snapshots", "snap-c", "snap-b", "--json"}},
		{"delete-snap-none", exitUsage, []string{"delete", "snap"}},
	} {
		kindsGolden(t, h, f, tc.code, tc.golden, tc.args...)
	}
	f.mu.Lock()
	f.snapshots = map[string]map[string]any{}
	f.status["DELETE /v1/snapshots/x"] = http.StatusInternalServerError
	f.mu.Unlock()
	if code := h.run("get", "snapshots"); code != exitOK || !strings.Contains(h.stderr.String(), "no snapshots") {
		t.Fatalf("empty = %d %q", code, h.stderr.String())
	}
	if code := h.run("delete", "snap", "x", "--json"); code != exitError || h.stdout.String() != "" || h.errorEnvelope().HTTPStatus != 500 {
		t.Fatalf("failed delete = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	f.mu.Lock()
	f.status["GET /v1/snapshots"] = http.StatusForbidden
	f.mu.Unlock()
	if code := h.run("get", "snapshots"); code != exitError {
		t.Fatalf("list refused = %d", code)
	}
}

// A page full of names that never moves the cursor stops instead of looping,
// and an unreadable snapshot is an error, not a blank row.
func TestSnapshotListEdges(t *testing.T) {
	stuck := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/snapshots":
			writeFakeJSON(w, http.StatusOK, map[string]any{"snapshots": []any{}, "has_more": true})
		case "/v1/snapshots/bad":
			writeFakeJSON(w, http.StatusOK, []int{1})
		}
	}))
	t.Cleanup(stuck.Close)
	h := newHarness(t)
	h.env["SB_API_URL"] = stuck.URL
	if code := h.run("get", "snapshots"); code != exitOK {
		t.Fatalf("stuck cursor = %d %q", code, h.stderr.String())
	}
	if code := h.run("get", "snap", "bad"); code != exitError || !strings.Contains(h.stderr.String(), "unreadable snapshot") {
		t.Fatalf("bad snapshot = %d %q", code, h.stderr.String())
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeFakeJSON(w, http.StatusOK, map[string]any{"snapshots": []any{1}, "tokens": []any{1}})
	}))
	t.Cleanup(bad.Close)
	h.env["SB_API_URL"] = bad.URL
	for _, args := range [][]string{{"get", "snap"}, {"get", "tokens"}} {
		if code := h.run(args...); code != exitError || !strings.Contains(h.stderr.String(), "unreadable") {
			t.Fatalf("%v unreadable = %d %q", args, code, h.stderr.String())
		}
	}
}

func TestTokenKind(t *testing.T) {
	h, f := newKindsHarness(t)
	kindsFixture(h, f)
	for _, tc := range []struct {
		golden string
		code   int
		args   []string
	}{
		{"get-tokens", exitOK, []string{"get", "tokens"}},
		{"get-tok-wide", exitOK, []string{"get", "tok", "-o", "wide"}},
		{"get-token-name", exitOK, []string{"get", "token", "-o", "name"}},
		{"get-token-by-id-json", exitOK, []string{"get", "tokens", "tok_aaaaaaaaaaaa", "-o", "json"}},
		{"get-token-by-name-yaml", exitOK, []string{"get", "tokens", "ci", "-o", "yaml"}},
		{"get-token-missing", exitError, []string{"get", "tokens", "nope"}},
		{"describe-token", exitOK, []string{"describe", "token", "tok_aaaaaaaaaaaa"}},
		{"describe-token-shared-name", exitOK, []string{"describe", "tok", "ci"}},
		{"describe-token-expired-now", exitOK, []string{"describe", "tok", "deploy"}},
		{"describe-token-json", exitOK, []string{"describe", "tokens", "deploy", "-o", "json"}},
		{"describe-token-missing", exitError, []string{"describe", "tok", "nope"}},
		{"delete-token", exitOK, []string{"delete", "token", "tok_cccccccccccc"}},
		{"delete-token-json", exitOK, []string{"delete", "tokens", "tok_bbbbbbbbbbbb", "tok_cccccccccccc", "--json"}},
		{"delete-token-by-name", exitUsage, []string{"delete", "token", "ci"}},
		{"delete-token-none", exitUsage, []string{"delete", "tok"}},
	} {
		kindsGolden(t, h, f, tc.code, tc.golden, tc.args...)
	}
	f.mu.Lock()
	f.tokens = nil
	f.status["DELETE /v1/tokens/tok_aaaaaaaaaaaa"] = http.StatusForbidden
	f.mu.Unlock()
	if code := h.run("get", "tokens"); code != exitOK || !strings.Contains(h.stderr.String(), "no API tokens") {
		t.Fatalf("empty = %d %q", code, h.stderr.String())
	}
	if code := h.run("delete", "token", "tok_aaaaaaaaaaaa"); code != exitError {
		t.Fatalf("refused delete = %d", code)
	}
	f.mu.Lock()
	f.status["GET /v1/tokens"] = http.StatusForbidden
	f.mu.Unlock()
	if code := h.run("describe", "token", "x"); code != exitError {
		t.Fatalf("refused describe = %d", code)
	}
}

func TestAPIResources(t *testing.T) {
	h, f := newKindsHarness(t)
	for _, tc := range []struct {
		golden string
		code   int
		args   []string
	}{
		{"api-resources", exitOK, []string{"api-resources"}},
		{"api-resources-wide", exitOK, []string{"api-resources", "-o", "wide"}},
		{"api-resources-name", exitOK, []string{"api-resources", "-o", "name"}},
		{"api-resources-json", exitOK, []string{"api-resources", "--json"}},
		{"api-resources-yaml", exitOK, []string{"api-resources", "--output", "yaml"}},
		{"api-resources-extra", exitUsage, []string{"api-resources", "sb"}},
		{"api-resources-bad-output", exitUsage, []string{"api-resources", "-o", "table"}},
		{"api-resources-bad-flag", exitUsage, []string{"api-resources", "--nope"}},
	} {
		kindsGolden(t, h, f, tc.code, tc.golden, tc.args...)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queries) != 0 {
		t.Fatalf("api-resources asked sandboxd: %v", f.queries)
	}
}

// Every kind in the table answers to all its names, in any case, and each
// short name is unique, so one word never means two kinds.
func TestKindTable(t *testing.T) {
	seen := map[string]string{}
	for _, k := range resourceKinds() {
		if k.get == nil || k.title == "" || k.singular == "" {
			t.Errorf("kind %s is missing get, a title or a singular name", k.plural)
		}
		for _, word := range append([]string{k.plural, k.singular}, k.short...) {
			if prev, dup := seen[word]; dup {
				t.Errorf("%q names both %s and %s", word, prev, k.plural)
			}
			seen[word] = k.plural
			got, ok := findKind(strings.ToUpper(word))
			if !ok || got.plural != k.plural {
				t.Errorf("findKind(%q) = %v %v", strings.ToUpper(word), got.plural, ok)
			}
		}
	}
	if _, ok := findKind("box"); ok {
		t.Fatal("box is not a kind")
	}
	if kindList() != "nodes, sandboxes, snapshots, tokens or jointokens" {
		t.Fatalf("kindList = %q", kindList())
	}
	// A kind without describe or delete is refused by name; the table has
	// none today, so call the dispatcher with one.
	h := newHarness(t)
	k := resourceKind{plural: "widgets", singular: "widget", get: getNodes}
	if code := h.app.dispatchKind(t.Context(), &commonFlags{}, "delete", kindCall{kind: k}); code != exitUsage || !strings.Contains(h.stderr.String(), "delete does not take widgets") {
		t.Fatalf("missing verb = %d %q", code, h.stderr.String())
	}
}

func TestCreateWarnsWhenTheNameIsAKind(t *testing.T) {
	h, _ := newKindsHarness(t)
	if code := h.run("create", "--name", "nodes"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	want := "aerolvm: warning: \"nodes\" is also a kind, so `aerolvm get nodes` lists nodes; reach this sandbox with `aerolvm get sb nodes`\n"
	if !strings.HasPrefix(h.stderr.String(), want) {
		t.Fatalf("stderr = %q", h.stderr.String())
	}
	// It is reachable the documented way.
	if code := h.run("get", "sb", "nodes", "-o", "name"); code != exitOK || h.stdout.String() != "sandbox/nodes\n" {
		t.Fatalf("get sb nodes = %d %q", code, h.stdout.String())
	}
	if code := h.run("describe", "sb", "nodes"); code != exitOK || !strings.Contains(h.stdout.String(), "Network:      open\n") {
		t.Fatalf("describe sb nodes = %d %q", code, h.stdout.String())
	}
	if code := h.run("create", "--name", "plain-box"); code != exitOK || strings.Contains(h.stderr.String(), "warning") {
		t.Fatalf("plain name warned: %q", h.stderr.String())
	}
}

func TestTopNodes(t *testing.T) {
	h, f := newKindsHarness(t)
	f.members = []map[string]any{
		{"node_id": "srv-a", "role": "server", "alive": true, "capacity": map[string]any{}},
		{"node_id": "wkr-1", "role": "worker", "alive": true, "capacity": map[string]any{"host_cpu_cores": 8, "host_memory_total_mb": 8192,
			"reserved_cpu": 2.5, "cpu_budget": 8, "reserved_memory_mb": 1024, "memory_budget_mb": 4096, "sandboxes_active": 4, "parked_slots": 1}},
		{"node_id": "wkr-2", "role": "worker", "alive": false, "capacity_stale": true, "capacity": map[string]any{"host_cpu_cores": 8}},
	}
	for _, tc := range []struct {
		golden string
		code   int
		args   []string
	}{
		{"top-nodes", exitOK, []string{"top", "nodes"}},
		{"top-node-one", exitOK, []string{"top", "no", "wkr-1"}},
		{"top-nodes-json", exitOK, []string{"top", "node", "--json"}},
		{"top-nodes-yaml", exitOK, []string{"top", "nodes", "wkr-2", "-o", "yaml"}},
		{"top-node-missing", exitError, []string{"top", "nodes", "ghost"}},
		{"top-no-kind", exitUsage, []string{"top"}},
		{"top-sandboxes", exitUsage, []string{"top", "sb"}},
		{"top-bad-output", exitUsage, []string{"top", "nodes", "-o", "wide"}},
		{"top-bad-flag", exitUsage, []string{"top", "--nope"}},
	} {
		kindsGolden(t, h, f, tc.code, tc.golden, tc.args...)
	}
	// A single node: no members, so /v1/capacity, named after the host.
	f.mu.Lock()
	f.members = nil
	f.capacity = map[string]any{"host_cpu_cores": 4, "host_memory_total_mb": 4096, "reserved_cpu": 1, "cpu_budget": 4,
		"reserved_memory_mb": 512, "memory_budget_mb": 2048, "sandboxes_active": 2}
	f.mu.Unlock()
	kindsGolden(t, h, f, exitOK, "top-single-node", "top", "nodes")
	f.mu.Lock()
	f.status["GET /v1/capacity"] = http.StatusForbidden
	f.mu.Unlock()
	if code := h.run("top", "nodes"); code != exitError {
		t.Fatalf("capacity refused = %d", code)
	}
	f.mu.Lock()
	f.status["GET /v1/cluster/members"] = http.StatusForbidden
	f.mu.Unlock()
	if code := h.run("top", "nodes"); code != exitError {
		t.Fatalf("members refused = %d", code)
	}
	delete(h.env, "SB_PAT_TOKEN")
	delete(h.env, "SB_API_URL")
	h.env["XDG_CONFIG_HOME"] = t.TempDir()
	f.mu.Lock()
	f.status = map[string]int{}
	f.mu.Unlock()
	if rec, err := h.app.localCapacity(t.Context(), &commonFlags{}); err == nil {
		t.Fatalf("localCapacity with no login = %+v", rec)
	}
}

// The kind fakes speak the server's JSON, so a renamed field shows up here.
func TestKindsFixtureDecodes(t *testing.T) {
	h, f := newKindsHarness(t)
	kindsFixture(h, f)
	for name, snap := range f.snapshots {
		raw, _ := json.Marshal(snap)
		var s models.SandboxSnapshot
		if err := json.Unmarshal(raw, &s); err != nil || s.Name != name {
			t.Fatalf("snapshot %s = %+v %v", name, s, err)
		}
	}
	for _, tok := range f.tokens {
		raw, _ := json.Marshal(tok)
		var a models.APIToken
		if err := json.Unmarshal(raw, &a); err != nil || a.ID == "" {
			t.Fatalf("token = %+v %v", a, err)
		}
	}
	if e := agenttools.Classify(notFoundAs(fmt.Errorf("plain"), "snapshot", "x", "l")); e.Message != "plain" {
		t.Fatalf("non-404 changed: %+v", e)
	}
}

func TestAgeLikeKubectl(t *testing.T) {
	now := kindsNow
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0s"}, {0, "0s"}, {90 * time.Second, "90s"}, {5 * time.Minute, "5m"}, {5*time.Minute + 7*time.Second, "5m7s"},
		{2 * time.Hour, "120m"}, {3 * time.Hour, "3h"}, {3*time.Hour + 4*time.Minute, "3h4m"}, {30 * time.Hour, "30h"},
		{3 * 24 * time.Hour, "3d"}, {3*24*time.Hour + 5*time.Hour, "3d5h"}, {40 * 24 * time.Hour, "40d"},
		{3 * 365 * 24 * time.Hour, "3y"}, {(3*365 + 4) * 24 * time.Hour, "3y4d"}, {10 * 365 * 24 * time.Hour, "10y"},
	} {
		if got := age(now, now.Add(-tc.d)); got != tc.want {
			t.Errorf("age(%s) = %q, want %q", tc.d, got, tc.want)
		}
	}
	if age(now, time.Time{}) != "-" || whenAgo(now, time.Time{}) != "-" {
		t.Fatal("a zero time is unknown")
	}
}

func TestSelectorParse(t *testing.T) {
	for _, bad := range []string{"a,,b", "=v", "!", "a=b=c", "a in (x)", "a!=b!", "a b"} {
		if _, err := parseSelector(bad); err == nil {
			t.Errorf("parseSelector(%q) accepted", bad)
		}
	}
	sel, err := parseSelector(" app=web , env!=prod, tier, !gpu, team==ml ")
	if err != nil {
		t.Fatal(err)
	}
	if eq := sel.equal(); len(eq) != 2 || eq["app"] != "web" || eq["team"] != "ml" {
		t.Fatalf("equal = %v", eq)
	}
	for _, tc := range []struct {
		tags map[string]string
		want bool
	}{
		{map[string]string{"app": "web", "tier": "x", "team": "ml"}, true},
		{map[string]string{"app": "web", "tier": "x", "team": "ml", "env": "dev"}, true},
		{map[string]string{"app": "web", "tier": "x", "team": "ml", "env": "prod"}, false},
		{map[string]string{"app": "web", "team": "ml"}, false},
		{map[string]string{"app": "web", "tier": "x", "team": "ml", "gpu": ""}, false},
		{map[string]string{"app": "db", "tier": "x", "team": "ml"}, false},
	} {
		if got := sel.matches(tc.tags); got != tc.want {
			t.Errorf("matches(%v) = %v, want %v", tc.tags, got, tc.want)
		}
	}
	if none, _ := parseSelector("  "); none.equal() != nil || !none.matches(nil) {
		t.Fatal("an empty selector matches everything and filters nothing")
	}
}
