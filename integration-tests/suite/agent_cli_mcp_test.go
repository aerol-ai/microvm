//go:build integration

package suite

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// UC-176..178: the aerolvm agent CLI, its stdio MCP server, and sandboxd's
// remote /mcp endpoint, driven against a live deployment
// (plans/mcp-server-and-agent-cli.md §8). The CLI is built from this tree, so
// a run tests the branch, not a release.

// agentImage has python for the dev server the expose steps start.
const agentImage = "python:3.12-alpine"

var (
	aerolvmOnce sync.Once
	aerolvmPath string
	aerolvmErr  error
)

func aerolvmBinary(t *testing.T) string {
	t.Helper()
	aerolvmOnce.Do(func() {
		dir, err := os.MkdirTemp("", "aerolvm-itest-")
		if err != nil {
			aerolvmErr = err
			return
		}
		aerolvmPath = filepath.Join(dir, "aerolvm")
		if out, err := exec.Command("go", "build", "-o", aerolvmPath, "../../cmd/aerolvm").CombinedOutput(); err != nil {
			aerolvmErr = fmt.Errorf("go build ./cmd/aerolvm: %v\n%s", err, out)
		}
	})
	if aerolvmErr != nil {
		t.Fatal(aerolvmErr)
	}
	return aerolvmPath
}

type cliResult struct {
	stdout, stderr string
	code           int
}

// aerolvm runs the CLI against apiURL with the scenario's token.
func aerolvm(t *testing.T, apiURL string, stdin io.Reader, args ...string) cliResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, aerolvmBinary(t), args...)
	cmd.Env = append(os.Environ(), "SB_API_URL="+apiURL, "SB_PAT_TOKEN="+sc.PAT, "AEROLVM_OUTPUT=")
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := cliResult{stdout: stdout.String(), stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.code = exit.ExitCode()
	case err != nil:
		t.Fatalf("aerolvm %v: %v", args, err)
	}
	return res
}

func (r cliResult) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.stdout), v); err != nil {
		t.Fatalf("stdout is not JSON: %v\nstdout: %s\nstderr: %s", err, r.stdout, r.stderr)
	}
}

// destroyByNameOnCleanup removes a sandbox the test made through the CLI or
// MCP, whatever state the test ended in.
func destroyByNameOnCleanup(t *testing.T, c *harness.Client, name string) {
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if sb, err := c.SDK().GetByName(ctx, name); err == nil {
			_ = sb.Destroy(ctx)
		}
	})
}

// fetchEventually polls a freshly exposed URL: routing, DNS and TLS can lag
// the API response by a few seconds.
func fetchEventually(t *testing.T, target string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				cancel()
				return
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		cancel()
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("%s never answered 200: %s", target, last)
}

// nonOwnerAPI returns a local address that reaches sandboxd on a node that
// does not own sandboxID, or skips when no such node is reachable over SSH.
func nonOwnerAPI(t *testing.T, c *harness.Client, sandboxID string) string {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	owner := resolvePlacementOwner(t, c, sandboxID)
	if owner == "" {
		t.Fatal("no placement owner recorded for the sandbox")
	}
	node, ok := pickBounceableNode(t, c, targets, owner)
	if !ok {
		t.Skipf("no SSH-reachable node other than the owner %s", owner)
	}
	t.Logf("owner %s; driving node %s", owner, node.Name)
	return "http://" + harness.SSHForward(t, node, "127.0.0.1:21212")
}

// UC-176 — the CLI flow an agent runs through a shell.
func TestAerolvmCLIFlow(t *testing.T) {
	harness.Require(t, sc, "UC-176")
	c := client(t)
	api := sc.BaseURL
	name := harness.UniqueName(sc, t)
	destroyByNameOnCleanup(t, c, name)

	var created struct {
		ID      string            `json:"id"`
		Name    string            `json:"name"`
		Created bool              `json:"created"`
		Tags    map[string]string `json:"tags"`
	}
	r := aerolvm(t, api, nil, "create", "--name", name, "--image", agentImage, "--destroy-if-idle", "1h", "--json")
	if r.code != 0 {
		t.Fatalf("create = %d: %s", r.code, r.stderr)
	}
	r.json(t, &created)
	if !created.Created || created.Name != name || created.Tags["aerolvm.created_by"] != "cli" {
		t.Fatalf("create = %+v", created)
	}
	// Retrying the create is how an agent recovers from a dropped
	// connection: it must return the same sandbox, not a second one.
	var again struct {
		ID      string `json:"id"`
		Created bool   `json:"created"`
	}
	r = aerolvm(t, api, nil, "create", "--name", name, "--image", agentImage, "--json")
	if r.code != 0 {
		t.Fatalf("repeat create = %d: %s", r.code, r.stderr)
	}
	r.json(t, &again)
	if again.Created || again.ID != created.ID {
		t.Fatalf("repeat create = %+v, want the existing %s", again, created.ID)
	}

	// exec streams output and exits with the command's own code.
	r = aerolvm(t, api, nil, "exec", name, "--no-stdin", "--", "echo hello-cli && exit 3")
	if r.code != 3 || r.stdout != "hello-cli\n" {
		t.Fatalf("exec = %d %q (stderr %q)", r.code, r.stdout, r.stderr)
	}
	// Piped stdin is forwarded.
	r = aerolvm(t, api, strings.NewReader("from-stdin"), "exec", name, "--", "cat")
	if r.code != 0 || r.stdout != "from-stdin" {
		t.Fatalf("exec with stdin = %d %q (stderr %q)", r.code, r.stdout, r.stderr)
	}

	// cp streams both ways; 1 MiB of random bytes must round-trip exactly.
	payload := make([]byte, 1<<20)
	_, _ = rand.Read(payload)
	local := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(local, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if r = aerolvm(t, api, nil, "cp", local, name+":/tmp/uc176.bin"); r.code != 0 {
		t.Fatalf("cp up = %d: %s", r.code, r.stderr)
	}
	if r = aerolvm(t, api, nil, "cp", name+":/tmp/uc176.bin", "-"); r.code != 0 || r.stdout != string(payload) {
		t.Fatalf("cp down = %d, %d bytes (want %d): %s", r.code, len(r.stdout), len(payload), r.stderr)
	}

	// A background dev server, exposed. expose is idempotent.
	if r = aerolvm(t, api, nil, "exec", name, "--background", "--", "cd /tmp && python3 -m http.server 8080"); r.code != 0 {
		t.Fatalf("exec --background = %d: %s", r.code, r.stderr)
	}
	var exposed struct {
		PublicURL string `json:"public_url"`
	}
	r = aerolvm(t, api, nil, "expose", name, "8080", "--json")
	if r.code != 0 {
		t.Fatalf("expose = %d: %s", r.code, r.stderr)
	}
	r.json(t, &exposed)
	if exposed.PublicURL == "" {
		t.Fatalf("expose printed no URL: %s", r.stdout)
	}
	if r = aerolvm(t, api, nil, "expose", name, "8080"); r.code != 0 || strings.TrimSpace(r.stdout) != exposed.PublicURL {
		t.Fatalf("repeat expose = %d %q, want %q", r.code, r.stdout, exposed.PublicURL)
	}
	if sc.Has(harness.CapDomain) {
		fetchEventually(t, exposed.PublicURL)
	}

	// On a cluster, the same name resolves through a node that does not own
	// the sandbox: the lookup and the exec are forwarded to the owner.
	if sc.Has(harness.CapCluster) {
		t.Run("non-owner-node", func(t *testing.T) {
			other := nonOwnerAPI(t, c, created.ID)
			r := aerolvm(t, other, nil, "exec", name, "--no-stdin", "--", "wc -c < /tmp/uc176.bin")
			if r.code != 0 || strings.TrimSpace(r.stdout) != fmt.Sprint(len(payload)) {
				t.Fatalf("exec via a non-owner node = %d %q (stderr %q)", r.code, r.stdout, r.stderr)
			}
		})
	}

	// destroy is idempotent, and the name is gone afterwards.
	for i := range 2 {
		if r = aerolvm(t, api, nil, "destroy", name); r.code != 0 {
			t.Fatalf("destroy #%d = %d: %s", i+1, r.code, r.stderr)
		}
	}
	r = aerolvm(t, api, nil, "get", name, "--json")
	if r.code != 1 || !strings.Contains(r.stderr, `"code":"not_found"`) {
		t.Fatalf("get after destroy = %d, stderr %q", r.code, r.stderr)
	}
}

// mcpCall calls a tool and decodes its structured result. A tool error is a
// test failure unless wantErr is set.
func mcpCall(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any, out any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if res.IsError {
		var text []string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text = append(text, tc.Text)
			}
		}
		t.Fatalf("%s returned a tool error: %s", tool, strings.Join(text, " "))
	}
	if out != nil {
		raw, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s result: %v (%s)", tool, err, raw)
		}
	}
}

func connectStdioMCP(t *testing.T, args ...string) *mcp.ClientSession {
	t.Helper()
	cmd := exec.Command(aerolvmBinary(t), append([]string{"mcp"}, args...)...)
	cmd.Env = append(os.Environ(), "SB_API_URL="+sc.BaseURL, "SB_PAT_TOKEN="+sc.PAT)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "aerolvm-itest"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect to aerolvm mcp: %v", err)
	}
	return cs
}

type execOut struct {
	ExitCode       int    `json:"exit_code"`
	Stdout         string `json:"stdout"`
	SandboxCreated bool   `json:"sandbox_created"`
}

// UC-177 — the stdio MCP server, as Claude Code or Cursor runs it.
func TestAerolvmMCPStdioFlow(t *testing.T) {
	harness.Require(t, sc, "UC-177")
	c := client(t)

	t.Run("unpinned", func(t *testing.T) {
		name := harness.UniqueName(sc, t)
		destroyByNameOnCleanup(t, c, name)
		cs := connectStdioMCP(t, "--toolsets", "all")
		defer cs.Close()

		var created struct {
			ID      string `json:"id"`
			Created bool   `json:"created"`
		}
		mcpCall(t, cs, "sandbox_create", map[string]any{"name": name, "image": agentImage}, &created)
		if !created.Created {
			t.Fatalf("sandbox_create = %+v", created)
		}
		var ex execOut
		mcpCall(t, cs, "exec", map[string]any{"sandbox": name, "command": "echo hello-mcp; exit 5"}, &ex)
		if ex.ExitCode != 5 || ex.Stdout != "hello-mcp\n" {
			t.Fatalf("exec = %+v", ex)
		}
		mcpCall(t, cs, "write_file", map[string]any{"sandbox": name, "path": "/tmp/uc177.txt", "content": "line one\nline two\n"}, nil)
		var read struct {
			Content string `json:"content"`
		}
		mcpCall(t, cs, "read_file", map[string]any{"sandbox": name, "path": "/tmp/uc177.txt"}, &read)
		if !strings.Contains(read.Content, "line two") {
			t.Fatalf("read_file = %q", read.Content)
		}
		var proc struct {
			SessionID string `json:"session_id"`
		}
		mcpCall(t, cs, "start_process", map[string]any{"sandbox": name, "command": "cd /tmp && python3 -m http.server 8080"}, &proc)
		if proc.SessionID == "" {
			t.Fatal("start_process returned no session_id")
		}
		var exposed struct {
			URL string `json:"url"`
		}
		mcpCall(t, cs, "expose_port", map[string]any{"sandbox": name, "port": 8080}, &exposed)
		if exposed.URL == "" {
			t.Fatal("expose_port returned no url")
		}
		if sc.Has(harness.CapDomain) {
			fetchEventually(t, exposed.URL)
		}
		var destroyed struct {
			Destroyed bool `json:"destroyed"`
		}
		mcpCall(t, cs, "sandbox_destroy", map[string]any{"sandbox": name}, &destroyed)
		if !destroyed.Destroyed {
			t.Fatalf("sandbox_destroy = %+v", destroyed)
		}
	})

	t.Run("pinned-lazy-ephemeral", func(t *testing.T) {
		name := harness.UniqueName(sc, t)
		destroyByNameOnCleanup(t, c, name)
		cs := connectStdioMCP(t, "--sandbox", name, "--create-if-missing", "--image", agentImage, "--ephemeral")

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		// Lazy: starting the server creates nothing.
		if _, err := c.SDK().GetByName(ctx, name); !errors.Is(err, microvm.ErrNotFound) {
			_ = cs.Close()
			t.Fatalf("before the first tool call, GetByName = %v; want not found", err)
		}
		var ex execOut
		mcpCall(t, cs, "exec", map[string]any{"command": "echo pinned"}, &ex)
		if ex.ExitCode != 0 || ex.Stdout != "pinned\n" {
			_ = cs.Close()
			t.Fatalf("exec = %+v", ex)
		}
		sb, err := c.SDK().GetByName(ctx, name)
		if err != nil {
			_ = cs.Close()
			t.Fatalf("after the first call, GetByName: %v", err)
		}
		// The idle defaults that stop a forgotten agent sandbox costing money.
		if sb.Lifecycle.StopIfIdleFor != 30*time.Minute || sb.Lifecycle.DestroyIfIdleFor != 24*time.Hour || sb.Tags["aerolvm.created_by"] != "mcp" {
			_ = cs.Close()
			t.Fatalf("lazily created sandbox: lifecycle %+v, tags %v", sb.Lifecycle, sb.Tags)
		}
		// --ephemeral: closing the session ends the server, which destroys it.
		if err := cs.Close(); err != nil {
			t.Logf("close: %v", err)
		}
		deadline := time.Now().Add(2 * time.Minute)
		for {
			_, err := c.SDK().GetByName(ctx, name)
			if errors.Is(err, microvm.ErrNotFound) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("ephemeral sandbox still there after the server exited: %v", err)
			}
			time.Sleep(2 * time.Second)
		}
	})
}

func connectRemoteMCP(t *testing.T, base, sandbox string, query url.Values) *mcp.ClientSession {
	t.Helper()
	q := url.Values{"sandbox": {sandbox}}
	for k, v := range query {
		q[k] = v
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:   base + "/mcp?" + q.Encode(),
		HTTPClient: &http.Client{Transport: bearerRoundTripper{token: sc.PAT}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "aerolvm-itest"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect to %s/mcp: %v", base, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

type bearerRoundTripper struct{ token string }

func (b bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// UC-178 — the remote endpoint: no install, just a URL and a token.
func TestRemoteMCPOnNonOwnerNode(t *testing.T) {
	harness.Require(t, sc, "UC-178")
	c := client(t)
	name := harness.UniqueName(sc, t)
	destroyByNameOnCleanup(t, c, name)

	// Through the API domain, so Caddy's route to /mcp is part of the proof.
	// The first call creates the sandbox and says so (eng re-review RR2).
	cs := connectRemoteMCP(t, sc.BaseURL, name, url.Values{"create_if_missing": {"true"}, "image": {agentImage}})
	var ex execOut
	mcpCall(t, cs, "exec", map[string]any{"command": "echo remote"}, &ex)
	if ex.ExitCode != 0 || ex.Stdout != "remote\n" || !ex.SandboxCreated {
		t.Fatalf("first remote exec = %+v; want output and sandbox_created", ex)
	}
	mcpCall(t, cs, "write_file", map[string]any{"path": "/tmp/uc178.txt", "content": "written-remotely\n"}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sb, err := c.SDK().GetByName(ctx, name)
	if err != nil {
		t.Fatalf("GetByName after the remote create: %v", err)
	}
	if sb.Tags["aerolvm.created_by"] != "mcp" {
		t.Fatalf("remote create tags = %v", sb.Tags)
	}

	// Now a node that doesn't own the sandbox serves the same pinned
	// session: it resolves the name and forwards each call to the owner.
	other := nonOwnerAPI(t, c, sb.ID)
	cs2 := connectRemoteMCP(t, other, name, nil)
	var read struct {
		Content string `json:"content"`
	}
	mcpCall(t, cs2, "read_file", map[string]any{"path": "/tmp/uc178.txt"}, &read)
	if read.Content != "written-remotely\n" {
		t.Fatalf("read_file via a non-owner node = %q", read.Content)
	}
	var ex2 execOut
	mcpCall(t, cs2, "exec", map[string]any{"command": "cat /tmp/uc178.txt"}, &ex2)
	if ex2.ExitCode != 0 || ex2.Stdout != "written-remotely\n" || ex2.SandboxCreated {
		t.Fatalf("exec via a non-owner node = %+v", ex2)
	}
}
