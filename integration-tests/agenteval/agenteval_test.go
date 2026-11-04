//go:build agenteval

package agenteval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// The five eval tasks (eng review D13). Pass criteria are loose on wording
// and strict on effect: each task checks the sandbox afterwards, not only
// what the model said.
//
// Environment:
//
//	ANTHROPIC_API_KEY          required
//	SB_API_URL, SB_PAT_TOKEN   the sandboxd to drive; a local single-node install
//	AEROLVM_EVAL_MODEL         model to evaluate (default DefaultModel)
//	AEROLVM_EVAL_IMAGE         image for tasks 1-4 (default python:3.12-alpine)
//	AEROLVM_EVAL_WASM_IMAGE    module ref for task 5; the task skips without it
//	AEROLVM_EVAL_WASM_COMMAND  command for task 5 (default "echo hello-wasm")
//	AEROLVM_EVAL_WASM_EXPECT   text task 5's answer must contain (default "hello-wasm")

const systemPrompt = "You are a coding agent with tools for AerolVM sandboxes, isolated Linux machines. Use the tools to do the task. When you are done, answer briefly."

type evalEnv struct {
	model *Anthropic
	sdk   *microvm.Client
	image string
}

func setup(t *testing.T) evalEnv {
	t.Helper()
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		t.Fatal("ANTHROPIC_API_KEY is required: this eval calls the Anthropic API")
	}
	if os.Getenv("SB_PAT_TOKEN") == "" {
		t.Fatal("SB_PAT_TOKEN (and SB_API_URL) must point at the sandboxd to drive")
	}
	model := os.Getenv("AEROLVM_EVAL_MODEL")
	if model == "" {
		model = DefaultModel
	}
	sdk, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: os.Getenv("SB_API_URL"), PATToken: os.Getenv("SB_PAT_TOKEN")})
	if err != nil {
		t.Fatal(err)
	}
	image := os.Getenv("AEROLVM_EVAL_IMAGE")
	if image == "" {
		image = "python:3.12-alpine"
	}
	t.Logf("model %s, image %s", model, image)
	return evalEnv{model: &Anthropic{APIKey: key, Model: model}, sdk: sdk, image: image}
}

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// aerolvm builds cmd/aerolvm from this tree: the eval grades the tool text
// about to ship, not an installed release.
func aerolvm(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "aerolvm-eval-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "aerolvm")
		if out, err := exec.Command("go", "build", "-o", binPath, "../../cmd/aerolvm").CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build ./cmd/aerolvm: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

// start runs `aerolvm mcp` with args, as an MCP client would, and opens a
// conversation over it.
func (e evalEnv) start(t *testing.T, args ...string) *Conversation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.Command(aerolvm(t), append([]string{"mcp"}, args...)...)
	cmd.Stderr = io.Discard
	session, err := mcp.NewClient(&mcp.Implementation{Name: "aerolvm-agenteval"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("start aerolvm mcp: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	conv, err := NewConversation(ctx, e.model, session, systemPrompt)
	if err != nil {
		t.Fatal(err)
	}
	return conv
}

func (e evalEnv) ask(t *testing.T, conv *Conversation, prompt string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	answer, err := conv.Ask(ctx, prompt)
	t.Logf("prompt: %s\ntool calls:\n%sanswer: %s", prompt, conv.Summary(), answer)
	if err != nil {
		t.Fatal(err)
	}
	return answer
}

// name returns a fresh sandbox name and destroys that sandbox at the end.
func (e evalEnv) name(t *testing.T, task string) string {
	t.Helper()
	name := "eval-" + task + "-" + token(t)[:8]
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if sb, err := e.sdk.GetByName(ctx, name); err == nil {
			_ = sb.Destroy(ctx)
		}
	})
	return name
}

// run executes a command in the sandbox directly, to check what the model
// did rather than trusting its answer.
func (e evalEnv) run(t *testing.T, name, command string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := e.sdk.GetByName(ctx, name)
	if err != nil {
		t.Fatalf("sandbox %s: %v", name, err)
	}
	res, err := sb.ExecCommand(ctx, command)
	if err != nil {
		t.Fatalf("check %q: %v", command, err)
	}
	return res.Stdout
}

func token(t *testing.T) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// Task 1: create a sandbox, run a command, report its output.
func TestEvalCreateAndExec(t *testing.T) {
	e := setup(t)
	name := e.name(t, "exec")
	conv := e.start(t)
	answer := e.ask(t, conv, fmt.Sprintf("Create a sandbox named %s from the image %s. Run `python3 -c 'print(6*7)'` in it and tell me exactly what it printed.", name, e.image))
	if !conv.Called("sandbox_create") || !conv.Called("exec") {
		t.Fatal("expected sandbox_create and exec")
	}
	if !strings.Contains(answer, "42") {
		t.Fatalf("answer does not report 42: %q", answer)
	}
}

// Task 2: write a file, read it back.
func TestEvalWriteThenRead(t *testing.T) {
	e := setup(t)
	name := e.name(t, "files")
	want := "eval-" + token(t)
	conv := e.start(t, "--sandbox", name, "--create-if-missing", "--image", e.image)
	answer := e.ask(t, conv, fmt.Sprintf("Create the file /work/notes.txt containing exactly the line %s. Then read the file back and tell me what it contains.", want))
	if !conv.Called("write_file") || !conv.Called("read_file") {
		t.Fatal("expected write_file and read_file")
	}
	if !strings.Contains(answer, want) {
		t.Fatalf("answer does not contain the file's text: %q", answer)
	}
	if got := e.run(t, name, "cat /work/notes.txt"); !strings.Contains(got, want) {
		t.Fatalf("/work/notes.txt = %q", got)
	}
}

// Task 3: a dev server that keeps running, published and fetched.
func TestEvalDevServer(t *testing.T) {
	e := setup(t)
	name := e.name(t, "serve")
	want := "eval-" + token(t)
	conv := e.start(t, "--sandbox", name, "--create-if-missing", "--image", e.image, "--toolsets", "all")
	e.ask(t, conv, fmt.Sprintf("Serve a web page from the sandbox: create /srv/index.html containing %s, start a web server on port 8000 serving /srv that keeps running in the background, publish port 8000, and give me its URL.", want))
	if !conv.Called("start_process") || !conv.Called("expose_port") {
		t.Fatal("expected start_process and expose_port")
	}
	var url string
	for _, s := range conv.Steps {
		if s.Tool == "expose_port" && !s.IsError {
			url, _ = s.Structured["url"].(string)
		}
	}
	if url == "" {
		t.Fatal("expose_port never returned a URL")
	}
	if body, err := fetch(url); err == nil && strings.Contains(body, want) {
		return
	} else {
		// A local install without a domain gives URLs this machine may not
		// reach; the server is still checked, from inside the sandbox.
		t.Logf("%s from here: %v; checking from inside the sandbox", url, err)
	}
	if got := e.run(t, name, "wget -qO- http://127.0.0.1:8000/"); !strings.Contains(got, want) {
		t.Fatalf("the server on :8000 answered %q", got)
	}
}

func fetch(url string) (string, error) {
	var last error
	for range 10 {
		resp, err := http.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return string(body), nil
			}
			err = fmt.Errorf("%s", resp.Status)
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return "", last
}

// Task 4: the pinned sandbox disappears between turns; the model is told
// (eng review D6) and recovers.
func TestEvalRecoverAfterRecreate(t *testing.T) {
	e := setup(t)
	name := e.name(t, "recreate")
	conv := e.start(t, "--sandbox", name, "--create-if-missing", "--image", e.image)
	e.ask(t, conv, "Create the file /work/state.txt containing v1.")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := e.sdk.GetByName(ctx, name)
	if err != nil {
		t.Fatalf("the first turn left no sandbox: %v", err)
	}
	if err := sb.Destroy(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := e.sdk.GetByName(ctx, name); errors.Is(err, microvm.ErrNotFound) {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("the sandbox never went away")
		}
		time.Sleep(time.Second)
	}

	before := len(conv.Steps)
	answer := e.ask(t, conv, "Read /work/state.txt and tell me what it says. If anything about the sandbox changed, say what happened and put the file back with v1.")
	notified := false
	for _, s := range conv.Steps[before:] {
		if s.Structured["sandbox_recreated"] == true {
			notified = true
		}
	}
	if !notified {
		t.Fatal("no tool result after the destroy carried sandbox_recreated")
	}
	lower := strings.ToLower(answer)
	if !strings.Contains(lower, "recreat") && !strings.Contains(lower, "new sandbox") && !strings.Contains(lower, "no longer") && !strings.Contains(lower, "gone") {
		t.Fatalf("the answer doesn't mention that the sandbox was replaced: %q", answer)
	}
	if got := e.run(t, name, "cat /work/state.txt"); !strings.Contains(got, "v1") {
		t.Fatalf("/work/state.txt after recovery = %q", got)
	}
}

// Task 5: exec on a WASM sandbox, which has no streaming exec (eng review D10).
func TestEvalExecOnWASM(t *testing.T) {
	module := os.Getenv("AEROLVM_EVAL_WASM_IMAGE")
	if module == "" {
		t.Skip("AEROLVM_EVAL_WASM_IMAGE not set (a module ref the sandboxd can run)")
	}
	e := setup(t)
	command := envOr("AEROLVM_EVAL_WASM_COMMAND", "echo hello-wasm")
	expect := envOr("AEROLVM_EVAL_WASM_EXPECT", "hello-wasm")
	name := e.name(t, "wasm")
	conv := e.start(t)
	answer := e.ask(t, conv, fmt.Sprintf("Create a sandbox named %s with runtime wasm and image %s, run `%s` in it, and tell me the output.", name, module, command))
	if !conv.Called("sandbox_create") || !conv.Called("exec") {
		t.Fatal("expected sandbox_create and exec")
	}
	ok := false
	for _, s := range conv.Steps {
		if s.Tool == "exec" && !s.IsError && s.Structured["exit_code"] == float64(0) {
			ok = true
		}
	}
	if !ok || !strings.Contains(answer, expect) {
		t.Fatalf("no successful exec, or the answer lacks %q: %q", expect, answer)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
