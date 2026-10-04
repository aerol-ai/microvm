package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

var mcpHandshake = []string{
	`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
	`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{"command":"echo hi"}}}`,
}

// rpcSession drives an MCP server over a pair of pipes and checks that
// every stdout line is a JSON-RPC message (stdout hygiene: stdout is the
// protocol channel, so nothing else may be written there).
type rpcSession struct {
	t     *testing.T
	in    io.WriteCloser
	lines *bufio.Scanner
}

func (r *rpcSession) send(msg string) {
	r.t.Helper()
	if _, err := io.WriteString(r.in, msg+"\n"); err != nil {
		r.t.Fatalf("send: %v", err)
	}
}

// waitFor reads stdout until the response with id arrives.
func (r *rpcSession) waitFor(id int) map[string]any {
	r.t.Helper()
	for r.lines.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(r.lines.Bytes(), &msg); err != nil || msg["jsonrpc"] != "2.0" {
			r.t.Fatalf("stdout line is not JSON-RPC: %q", r.lines.Text())
		}
		if got, ok := msg["id"].(float64); ok && int(got) == id {
			return msg
		}
	}
	r.t.Fatalf("stdout closed before response %d: %v", id, r.lines.Err())
	return nil
}

// handshake follows the protocol order: the client waits for the
// initialize response before it sends anything else.
func (r *rpcSession) handshake() map[string]any {
	r.t.Helper()
	r.send(mcpHandshake[0])
	r.waitFor(1)
	r.send(mcpHandshake[1])
	r.send(mcpHandshake[2])
	r.waitFor(2)
	r.send(mcpHandshake[3])
	return r.waitFor(3)
}

func runMCPInProcess(t *testing.T, h *harness, args ...string) (*rpcSession, <-chan int) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	h.app.stdin = inR
	h.app.stdout = outW
	done := make(chan int, 1)
	go func() {
		code := h.app.run(context.Background(), append([]string{"mcp"}, args...))
		_ = outW.Close()
		done <- code
	}()
	t.Cleanup(func() { _ = inW.Close() })
	return &rpcSession{t: t, in: inW, lines: bufio.NewScanner(outR)}, done
}

func waitExit(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(10 * time.Second):
		t.Fatal("aerolvm mcp did not exit")
		return -1
	}
}

func TestMCPStdioInProcess(t *testing.T) {
	h := newHarness(t)
	rpc, done := runMCPInProcess(t, h, "--sandbox", "my-agent", "--create-if-missing", "--ephemeral", "--image", "alpine")
	res := rpc.handshake()
	result := res["result"].(map[string]any)
	if result["isError"] == true || !strings.Contains(fmt.Sprint(result["content"]), "hi") {
		t.Fatalf("tools/call exec = %v", res)
	}
	// Closing stdin is a clean shutdown: --ephemeral destroys the sandbox.
	_ = rpc.in.Close()
	if code := waitExit(t, done); code != exitOK {
		t.Fatalf("exit = %d, stderr %q", code, h.stderr.String())
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if s.CreatePosts != 1 || s.DestroyCalls != 1 || s.LastCreate.Tags["aerolvm.created_by"] != "mcp" {
			t.Fatalf("creates %d destroys %d tags %v", s.CreatePosts, s.DestroyCalls, s.LastCreate.Tags)
		}
	})
}

func TestMCPSigtermShutsDown(t *testing.T) {
	h := newHarness(t)
	rpc, done := runMCPInProcess(t, h, "--sandbox", "my-agent", "--create-if-missing", "--ephemeral")
	rpc.handshake()
	h.interrupt <- syscall.SIGTERM
	if code := waitExit(t, done); code != exitOK {
		t.Fatalf("exit after SIGTERM = %d", code)
	}
	h.fake.Observe(func(s *agenttoolstest.Server) {
		if s.DestroyCalls != 1 {
			t.Fatalf("destroys = %d, want 1", s.DestroyCalls)
		}
	})
}

func TestMCPArgumentErrors(t *testing.T) {
	h := newHarness(t)
	cases := map[string][]string{
		"--toolsets":          {"mcp", "--toolsets", "code"},
		"--create-if-missing": {"mcp", "--create-if-missing"},
		"unexpected":          {"mcp", "extra"},
		"-nope":               {"mcp", "--nope"},
	}
	for want, args := range cases {
		if code := h.run(args...); code != exitUsage || !strings.Contains(h.stderr.String(), want) {
			t.Fatalf("%v = %d %q, want usage naming %s", args, code, h.stderr.String(), want)
		}
	}
	h.env["SB_PAT_TOKEN"] = ""
	t.Setenv("SB_PAT_TOKEN", "")
	if code := h.run("mcp"); code != exitError || !strings.Contains(h.stderr.String(), "SB_PAT_TOKEN") {
		t.Fatalf("mcp without a token = %d %q", code, h.stderr.String())
	}
}

func TestMCPDebugAndRunError(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	rpc, done := runMCPInProcess(t, h, "--sandbox", "box", "--debug")
	rpc.handshake()
	_ = rpc.in.Close()
	waitExit(t, done)
	if !strings.Contains(h.stderr.String(), "Authorization: [REDACTED]") || strings.Contains(h.stderr.String(), agenttoolstest.Token) {
		t.Fatalf("mcp --debug stderr = %q", h.stderr.String())
	}
}

// TestMCPConfigNeverPrintsToken is the §5.3/§6 required proof.
func TestMCPConfigNeverPrintsToken(t *testing.T) {
	h := newHarness(t)
	h.env["SB_PAT_TOKEN"] = "secret-token-value"
	h.env["SB_API_URL"] = "https://sandbox.example.com"
	for _, client := range mcpClients {
		if code := h.run("mcp", "config", client, "--sandbox", "my-agent", "--create-if-missing", "--toolsets", "all"); code != exitOK {
			t.Fatalf("config %s = %d %q", client, code, h.stderr.String())
		}
		out := h.stdout.String() + h.stderr.String()
		if strings.Contains(out, "secret-token-value") {
			t.Fatalf("config %s printed the token:\n%s", client, out)
		}
		if !strings.Contains(h.stdout.String(), "--create-if-missing") || !strings.Contains(h.stdout.String(), "https://sandbox.example.com") {
			t.Fatalf("config %s = %s", client, h.stdout.String())
		}
	}
	h.run("mcp", "config", "claude-code", "--sandbox", "my-agent")
	if got := h.stdout.String(); got != "claude mcp add aerolvm -e SB_API_URL=https://sandbox.example.com -e SB_PAT_TOKEN=\"$SB_PAT_TOKEN\" -- aerolvm mcp --sandbox my-agent\n" {
		t.Fatalf("claude-code config = %q", got)
	}
	h.run("mcp", "config", "vscode")
	if !strings.Contains(h.stdout.String(), "${input:aerolvm-token}") {
		t.Fatalf("vscode config = %s", h.stdout.String())
	}
	delete(h.env, "SB_API_URL")
	h.run("mcp", "config", "cursor")
	if !strings.Contains(h.stdout.String(), "${env:SB_PAT_TOKEN}") || !strings.Contains(h.stdout.String(), "http://127.0.0.1:21212") {
		t.Fatalf("cursor config = %s", h.stdout.String())
	}
	for _, args := range [][]string{{"mcp", "config"}, {"mcp", "config", "emacs"}, {"mcp", "config", "cursor", "--toolsets", "nope"}, {"mcp", "config", "cursor", "--bad"}} {
		if code := h.run(args...); code != exitUsage {
			t.Fatalf("%v = %d", args, code)
		}
	}
}

// TestMCPSpawnedBinary is the stdout-hygiene and --ephemeral proof against
// the real binary: every stdout line is JSON-RPC, and closing stdin or
// sending SIGTERM destroys the pinned sandbox exactly once.
func TestMCPSpawnedBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and spawns the binary")
	}
	bin := filepath.Join(t.TempDir(), "aerolvm")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, how := range []string{"stdin-eof", "sigterm"} {
		t.Run(how, func(t *testing.T) {
			fake := agenttoolstest.New(t)
			cmd := exec.Command(bin, "mcp", "--sandbox", "my-agent", "--create-if-missing", "--ephemeral")
			cmd.Env = append(os.Environ(), "SB_API_URL="+fake.URL, "SB_PAT_TOKEN="+agenttoolstest.Token)
			stdin, _ := cmd.StdinPipe()
			stdout, _ := cmd.StdoutPipe()
			cmd.Stderr = io.Discard
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			rpc := &rpcSession{t: t, in: stdin, lines: bufio.NewScanner(stdout)}
			res := rpc.handshake()
			if res["result"].(map[string]any)["isError"] == true {
				t.Fatalf("exec = %v", res)
			}
			if how == "sigterm" {
				_ = cmd.Process.Signal(syscall.SIGTERM)
			} else {
				_ = stdin.Close()
			}
			// Drain stdout to the end, still checking every line.
			for rpc.lines.Scan() {
				var msg map[string]any
				if err := json.Unmarshal(rpc.lines.Bytes(), &msg); err != nil || msg["jsonrpc"] != "2.0" {
					t.Fatalf("stdout line is not JSON-RPC: %q", rpc.lines.Text())
				}
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("exit: %v", err)
			}
			fake.Observe(func(s *agenttoolstest.Server) {
				if s.DestroyCalls != 1 {
					t.Fatalf("destroys = %d, want exactly 1", s.DestroyCalls)
				}
			})
		})
	}
}
