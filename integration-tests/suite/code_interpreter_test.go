//go:build integration

package suite

// Live checks for the stateful code interpreter (plans/code-interpreter.md):
// the AerolVM Go SDK on every container and VM runtime, the pinned Daytona Go
// SDK through the /daytona facade, E2B's NDJSON /execute through the E2B
// runtime proxy (sandbox port 49999), a run driven from a node that does not
// own the sandbox, and the other languages through RunCodeOptions.Language.
// Every call runs through the ingress, the facade or /v1 toolbox proxy and,
// on a cluster, a forward to the owner, so these are the cases that prove the
// WebSocket and the NDJSON stream survive the whole path.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
	daytonasdk "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	daytonaoptions "github.com/daytonaio/daytona/libs/sdk-go/pkg/options"
	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

// interpImage has python3 and nothing else the interpreter needs. It is
// also what E2B's code-interpreter-v1 template maps to by default (D10), so
// the E2B and SDK cases see the same guest.
const interpImage = "python:3.12-slim"

// interpCreateTimeout covers a cold pull of a large image (r-base is close
// to 1 GB) or a Firecracker rootfs built from an image on a fresh node.
const interpCreateTimeout = 10 * time.Minute

// interpSandbox creates a sandbox for the interpreter cases from image on
// runtime and waits until it has started. It is private (no public route):
// everything here goes through the toolbox proxy.
func interpSandbox(t *testing.T, runtime, image string) *microvm.Sandbox {
	t.Helper()
	return interpSandboxCmd(t, runtime, image, nil)
}

// interpSandboxCmd creates the sandbox with cmd as its main program (the
// image's own command when cmd is nil).
func interpSandboxCmd(t *testing.T, runtime, image string, cmd []string) *microvm.Sandbox {
	t.Helper()
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), interpCreateTimeout)
	defer cancel()
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t), Runtime: runtime, Image: image, ContainerCommand: cmd,
	})
	if err != nil {
		t.Fatalf("create a %s sandbox from %s: %v", runtime, image, err)
	}
	t.Cleanup(func() { destroyBest(c, sb.ID) })
	interpWaitStarted(t, sb, interpCreateTimeout)
	return sb
}

// interpWaitStarted is waitRunning with a deadline that fits a large image.
func interpWaitStarted(t *testing.T, sb *microvm.Sandbox, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for string(sb.Status) != "started" {
		if string(sb.Status) == "error" {
			t.Fatalf("sandbox %s entered error state: %s", sb.ID, sb.LastError)
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s never reached started (last status %q)", sb.ID, sb.Status)
		}
		time.Sleep(2 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := sb.Refresh(ctx)
		cancel()
		if err != nil {
			t.Fatalf("refresh %s: %v", sb.ID, err)
		}
	}
}

// interpRun runs code and fails the test when the run itself fails (an SDK
// error, not an exception in the code).
func interpRun(t *testing.T, ctx context.Context, sb *microvm.Sandbox, code string, opts sdktypes.RunCodeOptions) *sdktypes.Execution {
	t.Helper()
	exec, err := sb.RunCode(ctx, code, opts)
	if err != nil {
		t.Fatalf("RunCode(%q): %v", code, err)
	}
	if exec == nil {
		t.Fatalf("RunCode(%q) returned no execution", code)
	}
	return exec
}

func interpStdout(exec *sdktypes.Execution) string { return strings.Join(exec.Logs.Stdout, "") }

// interpNoError fails when the code raised.
func interpNoError(t *testing.T, code string, exec *sdktypes.Execution) {
	t.Helper()
	if exec.Error != nil {
		t.Fatalf("RunCode(%q) raised %s: %s\n%s", code, exec.Error.Name, exec.Error.Value, exec.Error.Traceback)
	}
}

// timedChunks records when each streamed chunk arrived, so a case can tell
// output that streamed from output delivered at the end.
type timedChunks struct {
	mu     sync.Mutex
	text   strings.Builder
	firsts []time.Time
}

func (c *timedChunks) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.text.WriteString(s)
	c.firsts = append(c.firsts, time.Now())
}

func (c *timedChunks) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.text.String()
}

func (c *timedChunks) first() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.firsts) == 0 {
		return time.Time{}, false
	}
	return c.firsts[0], true
}

// streamingCode prints, sleeps, then prints again: when "first" arrives at
// least streamGap before the run ends, it was streamed, not buffered by any
// hop (toolbox proxy, facade, cluster forward, ingress) until the end.
const (
	streamingCode = "import time\nprint('first')\ntime.sleep(4)\nprint('second')"
	streamGap     = 2 * time.Second
)

// interpBattery is the per-runtime check list of UC-707..709, one subtest
// each so a failure names what broke and the rest still run. Each subtest
// sets the variables it reads, so they do not depend on each other's order.
func interpBattery(t *testing.T, sb *microvm.Sandbox) {
	t.Run("state and main result", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		first := interpRun(t, ctx, sb, "x = 5", sdktypes.RunCodeOptions{})
		interpNoError(t, "x = 5", first)
		second := interpRun(t, ctx, sb, "print(x)\nx * 2", sdktypes.RunCodeOptions{})
		interpNoError(t, "print(x); x * 2", second)
		if got := second.Text(); got != "10" {
			t.Fatalf("main result = %q, want 10 (results %+v)", got, second.Results)
		}
		if got := interpStdout(second); got != "5\n" {
			t.Fatalf("stdout = %q, want \"5\\n\"", got)
		}
		if first.ExecutionCount == nil || second.ExecutionCount == nil || *second.ExecutionCount <= *first.ExecutionCount {
			t.Fatalf("execution counts %v then %v: want two increasing counts", first.ExecutionCount, second.ExecutionCount)
		}
	})

	t.Run("exception", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		exec := interpRun(t, ctx, sb, "before_error = 1\n1/0", sdktypes.RunCodeOptions{})
		if exec.Error == nil || exec.Error.Name != "ZeroDivisionError" || !strings.Contains(exec.Error.Value, "division") {
			t.Fatalf("Execution.Error = %+v, want ZeroDivisionError", exec.Error)
		}
		if exec.Error.Traceback == "" {
			t.Fatal("the exception has no traceback")
		}
		// The context survives its exception, with what ran before it.
		after := interpRun(t, ctx, sb, "before_error + 1", sdktypes.RunCodeOptions{})
		if after.Text() != "2" {
			t.Fatalf("after an exception: result %q (error %+v), want 2", after.Text(), after.Error)
		}
	})

	t.Run("stdout streams", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		var chunks timedChunks
		exec := interpRun(t, ctx, sb, streamingCode, sdktypes.RunCodeOptions{OnStdout: chunks.add})
		ended := time.Now()
		interpNoError(t, streamingCode, exec)
		if got := chunks.String(); got != "first\nsecond\n" {
			t.Fatalf("OnStdout got %q, want \"first\\nsecond\\n\"", got)
		}
		if got := interpStdout(exec); got != "first\nsecond\n" {
			t.Fatalf("Logs.Stdout = %q", got)
		}
		if at, _ := chunks.first(); ended.Sub(at) < streamGap {
			t.Fatalf("the first chunk arrived %v before the run ended: output was held back, not streamed", ended.Sub(at))
		}
	})

	t.Run("per-run envs", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		code := "import os\nprint(os.environ.get('UC_INTERP_ENV'))"
		with := interpRun(t, ctx, sb, code, sdktypes.RunCodeOptions{Envs: map[string]string{"UC_INTERP_ENV": "per-run"}})
		if got := interpStdout(with); got != "per-run\n" {
			t.Fatalf("with envs: stdout %q (error %+v), want per-run", got, with.Error)
		}
		without := interpRun(t, ctx, sb, code, sdktypes.RunCodeOptions{})
		if got := interpStdout(without); got != "None\n" {
			t.Fatalf("the next run still sees the env: stdout %q, want None", got)
		}
	})

	t.Run("300 KB print arrives whole", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		const size = 300_000
		exec := interpRun(t, ctx, sb, fmt.Sprintf("print('x' * %d)", size), sdktypes.RunCodeOptions{})
		interpNoError(t, "large print", exec)
		got := interpStdout(exec)
		if len(got) != size+1 || strings.Trim(got, "x") != "\n" {
			t.Fatalf("stdout is %d bytes in %d chunks, want %d x's and a newline", len(got), len(exec.Logs.Stdout), size)
		}
	})

	t.Run("timeout keeps state", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		interpNoError(t, "kept = 'yes'", interpRun(t, ctx, sb, "kept = 'yes'", sdktypes.RunCodeOptions{}))
		two := 2
		start := time.Now()
		exec, err := sb.RunCode(ctx, "import time\ntime.sleep(60)", sdktypes.RunCodeOptions{TimeoutSeconds: &two})
		if !errors.Is(err, microvm.ErrCodeRunTimeout) {
			t.Fatalf("a run past its 2 s timeout returned %v (execution %+v), want ErrCodeRunTimeout", err, exec)
		}
		var runErr *microvm.CodeRunError
		if !errors.As(err, &runErr) || runErr.Execution == nil {
			t.Fatalf("the timeout error carries no partial execution: %#v", err)
		}
		if took := time.Since(start); took > 30*time.Second {
			t.Fatalf("the 2 s timeout took %v to end the run", took)
		}
		// time.sleep gives way to the interrupt, so the process lives on.
		after := interpRun(t, ctx, sb, "print(kept)", sdktypes.RunCodeOptions{})
		if got := interpStdout(after); got != "yes\n" {
			t.Fatalf("after the timeout: stdout %q (error %+v), want the variable kept", got, after.Error)
		}
	})

	t.Run("cancel interrupts and keeps state", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		interpNoError(t, "kept_c = 3", interpRun(t, ctx, sb, "kept_c = 3", sdktypes.RunCodeOptions{}))
		runCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		exec, err := sb.RunCode(runCtx, "import time\ntime.sleep(60)", sdktypes.RunCodeOptions{})
		stop()
		if err != nil || exec == nil || !exec.Interrupted {
			t.Fatalf("a cancelled run returned %+v, %v: want Interrupted and no error", exec, err)
		}
		after := interpRun(t, ctx, sb, "kept_c * 14", sdktypes.RunCodeOptions{})
		if after.Text() != "42" {
			t.Fatalf("after the interrupt: result %q (error %+v), want 42", after.Text(), after.Error)
		}
	})

	t.Run("ignored interrupt kills the context", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cc, err := sb.CreateCodeContext(ctx, sdktypes.CodeContextOptions{})
		if err != nil {
			t.Fatalf("CreateCodeContext: %v", err)
		}
		t.Cleanup(func() { _ = sb.DeleteCodeContext(context.Background(), cc.ID) })
		on := sdktypes.RunCodeOptions{ContextID: cc.ID}
		interpNoError(t, "doomed = 1", interpRun(t, ctx, sb, "doomed = 1", on))
		two := 2
		ignore := "import signal, time\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\ntime.sleep(60)"
		_, err = sb.RunCode(ctx, ignore, sdktypes.RunCodeOptions{ContextID: cc.ID, TimeoutSeconds: &two})
		if !errors.Is(err, microvm.ErrCodeRunTimeout) {
			t.Fatalf("a run that ignores SIGINT returned %v, want ErrCodeRunTimeout", err)
		}
		// Killed after the grace: the context keeps its id and starts a
		// fresh process on its next run.
		after := interpRun(t, ctx, sb, "print('doomed' in globals())", on)
		if got := interpStdout(after); got != "False\n" {
			t.Fatalf("after the kill: stdout %q (error %+v), want a fresh process", got, after.Error)
		}
	})

	t.Run("contexts", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		interpNoError(t, "only_default = 1", interpRun(t, ctx, sb, "only_default = 1", sdktypes.RunCodeOptions{}))
		cc, err := sb.CreateCodeContext(ctx, sdktypes.CodeContextOptions{Cwd: "/tmp"})
		if err != nil {
			t.Fatalf("CreateCodeContext: %v", err)
		}
		if cc.ID == "" || cc.Language != "python" || cc.Cwd != "/tmp" || !cc.Active || cc.CreatedAt == "" {
			t.Fatalf("created context = %+v, want an active python context in /tmp", cc)
		}
		on := sdktypes.RunCodeOptions{ContextID: cc.ID}
		interpNoError(t, "y = 'iso'", interpRun(t, ctx, sb, "y = 'iso'", on))
		iso := interpRun(t, ctx, sb, "import os\nprint(y, 'only_default' in globals(), os.getcwd())", on)
		if got := interpStdout(iso); got != "iso False /tmp\n" {
			t.Fatalf("in the context: stdout %q (error %+v), want its own state and cwd", got, iso.Error)
		}

		list, err := sb.ListCodeContexts(ctx)
		if err != nil {
			t.Fatalf("ListCodeContexts: %v", err)
		}
		if !hasCodeContext(list, cc.ID) || hasCodeContext(list, "default") {
			t.Fatalf("ListCodeContexts = %+v, want %s listed and default left out", list, cc.ID)
		}
		got, err := sb.GetCodeContext(ctx, cc.ID)
		if err != nil || got.ID != cc.ID || got.Cwd != "/tmp" {
			t.Fatalf("GetCodeContext = %+v, %v", got, err)
		}

		restarted, err := sb.RestartCodeContext(ctx, cc.ID)
		if err != nil || restarted.ID != cc.ID {
			t.Fatalf("RestartCodeContext = %+v, %v; want the same id", restarted, err)
		}
		wiped := interpRun(t, ctx, sb, "y", on)
		if wiped.Error == nil || wiped.Error.Name != "NameError" {
			t.Fatalf("after a restart: error %+v, want NameError", wiped.Error)
		}
		cwd := interpRun(t, ctx, sb, "import os\nprint(os.getcwd())", on)
		if got := interpStdout(cwd); got != "/tmp\n" {
			t.Fatalf("after a restart: cwd %q, want /tmp re-applied", got)
		}

		if err := sb.DeleteCodeContext(ctx, cc.ID); err != nil {
			t.Fatalf("DeleteCodeContext: %v", err)
		}
		if list, err := sb.ListCodeContexts(ctx); err != nil || hasCodeContext(list, cc.ID) {
			t.Fatalf("after delete: ListCodeContexts = %+v, %v", list, err)
		}
		if _, err := sb.GetCodeContext(ctx, cc.ID); !errors.Is(err, microvm.ErrNotFound) {
			t.Fatalf("GetCodeContext of a deleted context = %v, want ErrNotFound", err)
		}
		if err := sb.DeleteCodeContext(ctx, cc.ID); !errors.Is(err, microvm.ErrNotFound) {
			t.Fatalf("a second DeleteCodeContext = %v, want ErrNotFound", err)
		}
		if _, err := sb.RunCode(ctx, "1", on); err == nil {
			t.Fatal("RunCode in a deleted context succeeded")
		}
	})
}

func hasCodeContext(list []sdktypes.CodeContext, id string) bool {
	for _, c := range list {
		if c.ID == id {
			return true
		}
	}
	return false
}

// UC-707 — the Go SDK code interpreter on the default container runtime
// (containerd with runc on AWS, dockerd locally).
func TestCodeInterpDocker(t *testing.T) {
	harness.Require(t, sc, "UC-707")
	interpBattery(t, interpSandbox(t, "docker", interpImage))
}

// UC-708 — the same on gVisor.
func TestCodeInterpGvisor(t *testing.T) {
	harness.Require(t, sc, "UC-708")
	interpBattery(t, interpSandbox(t, "gvisor", interpImage))
}

// UC-709 — the same on Firecracker, created from the image: a template keeps
// the toolboxd it was built with, which may predate the interpreter.
func TestCodeInterpFirecracker(t *testing.T) {
	harness.Require(t, sc, "UC-709")
	interpBattery(t, interpSandbox(t, "firecracker", interpImage))
}

// daytonaInterp opens sandbox id with the pinned Daytona Go SDK.
func daytonaInterp(t *testing.T, ctx context.Context, id string) *daytonasdk.CodeInterpreterService {
	t.Helper()
	dc, err := daytonasdk.NewClientWithConfig(&daytonatypes.DaytonaConfig{
		APIKey: sc.PAT,
		APIUrl: strings.TrimRight(sc.BaseURL, "/") + "/daytona",
	})
	if err != nil {
		t.Fatalf("Daytona SDK client: %v", err)
	}
	t.Cleanup(func() { _ = dc.Close(context.Background()) })
	dsb, err := dc.Get(ctx, id)
	if err != nil {
		t.Fatalf("Daytona SDK Get(%s): %v", id, err)
	}
	return dsb.CodeInterpreter
}

// daytonaRunCode runs code with the Daytona SDK and returns its result and
// the stdout it streamed. The SDK's channels hold ten messages, so they are
// drained while the run goes on or a chatty run would stall its reader.
func daytonaRunCode(t *testing.T, ctx context.Context, ci *daytonasdk.CodeInterpreterService, code string, opts ...func(*daytonaoptions.RunCode)) (*daytonatypes.ExecutionResult, string) {
	t.Helper()
	ch, err := ci.RunCode(ctx, code, opts...)
	if err != nil {
		t.Fatalf("Daytona RunCode(%q): %v", code, err)
	}
	var streamed strings.Builder
	stdout, stderr, errs := ch.Stdout, ch.Stderr, ch.Errors
	for stdout != nil || stderr != nil || errs != nil {
		select {
		case m, ok := <-stdout:
			if !ok {
				stdout = nil
				continue
			}
			streamed.WriteString(m.Text)
		case _, ok := <-stderr:
			if !ok {
				stderr = nil
			}
		case _, ok := <-errs:
			if !ok {
				errs = nil
			}
		case <-ctx.Done():
			t.Fatalf("Daytona RunCode(%q): no end before %v", code, ctx.Err())
		}
	}
	res, ok := <-ch.Done
	if !ok || res == nil {
		t.Fatalf("Daytona RunCode(%q): the SDK sent no result", code)
	}
	return res, streamed.String()
}

// UC-710 — the code interpreter through the /daytona facade with the pinned
// Daytona Go SDK (v0.177.0, go.mod).
func TestCodeInterpDaytonaSDK(t *testing.T) {
	harness.Require(t, sc, "UC-710")
	sb := interpSandbox(t, "docker", interpImage)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	ci := daytonaInterp(t, ctx, sb.ID)

	res, _ := daytonaRunCode(t, ctx, ci, "x = 5")
	if res.Error != nil {
		t.Fatalf("x = 5: %+v", res.Error)
	}
	res, streamed := daytonaRunCode(t, ctx, ci, "print(x * 2)")
	if res.Error != nil || res.Stdout != "10\n" || streamed != "10\n" {
		t.Fatalf("print(x * 2): stdout %q, streamed %q, error %+v; want the default context to keep x", res.Stdout, streamed, res.Error)
	}
	res, _ = daytonaRunCode(t, ctx, ci, "1/0")
	if res.Error == nil || res.Error.Name != "ZeroDivisionError" {
		t.Fatalf("1/0: error %+v, want ZeroDivisionError", res.Error)
	}
	res, _ = daytonaRunCode(t, ctx, ci, "import os\nprint(os.environ.get('UC710'))", daytonaoptions.WithEnv(map[string]string{"UC710": "per-run"}))
	if res.Stdout != "per-run\n" {
		t.Fatalf("envs: stdout %q (error %+v)", res.Stdout, res.Error)
	}
	if res, _ = daytonaRunCode(t, ctx, ci, "import os\nprint(os.environ.get('UC710'))"); res.Stdout != "None\n" {
		t.Fatalf("the env outlived its run: stdout %q", res.Stdout)
	}

	cwd := "/tmp"
	info, err := ci.CreateContext(ctx, &cwd)
	if err != nil {
		t.Fatalf("CreateContext: %v", err)
	}
	id, _ := info["id"].(string)
	if id == "" || info["language"] != "python" || info["cwd"] != "/tmp" || info["active"] != true || info["createdAt"] == "" {
		t.Fatalf("CreateContext = %v, want an active python context in /tmp with all five fields", info)
	}
	if res, _ = daytonaRunCode(t, ctx, ci, "y = 41", daytonaoptions.WithCustomContext(id)); res.Error != nil {
		t.Fatalf("y = 41 in the new context: %+v", res.Error)
	}
	res, _ = daytonaRunCode(t, ctx, ci, "import os\nprint(y + 1, 'x' in globals(), os.getcwd())", daytonaoptions.WithCustomContext(id))
	if res.Stdout != "42 False /tmp\n" {
		t.Fatalf("in the new context: stdout %q (error %+v)", res.Stdout, res.Error)
	}
	list, err := ci.ListContexts(ctx)
	if err != nil {
		t.Fatalf("ListContexts: %v", err)
	}
	if !daytonaHasContext(list, id) || daytonaHasContext(list, "default") {
		t.Fatalf("ListContexts = %v, want %s listed and default left out", list, id)
	}

	// v0.177 maps only close 4001 to TimeoutError (Daytona's toolbox moved
	// to 4008 later); our close 4008 reaches it as a read failure, which the
	// SDK names ConnectionError. The newer TS and Python SDKs (UC-718/719)
	// see a real timeout error.
	start := time.Now()
	res, _ = daytonaRunCode(t, ctx, ci, "import time\ntime.sleep(60)", daytonaoptions.WithInterpreterTimeout(2*time.Second))
	if res.Error == nil || res.Error.Name != "ConnectionError" || !strings.Contains(res.Error.Value, "4008") {
		t.Fatalf("a run past its 2 s timeout ended with %+v, want the SDK's ConnectionError naming close 4008", res.Error)
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("the 2 s timeout took %v", took)
	}
	if res, _ = daytonaRunCode(t, ctx, ci, "print(x)"); res.Stdout != "5\n" {
		t.Fatalf("after the timeout: stdout %q (error %+v), want the default context's x", res.Stdout, res.Error)
	}

	if err := ci.DeleteContext(ctx, id); err != nil {
		t.Fatalf("DeleteContext: %v", err)
	}
	if list, err := ci.ListContexts(ctx); err != nil || daytonaHasContext(list, id) {
		t.Fatalf("after delete: ListContexts = %v, %v", list, err)
	}
	if err := ci.DeleteContext(ctx, id); err == nil {
		t.Fatal("deleting a deleted context succeeded, want 404")
	}
	if err := ci.DeleteContext(ctx, "default"); err == nil {
		t.Fatal("deleting the default context succeeded, want 400")
	}
}

func daytonaHasContext(list []map[string]any, id string) bool {
	for _, c := range list {
		if c["id"] == id {
			return true
		}
	}
	return false
}

// e2bInterp talks to one sandbox's E2B code interpreter (port 49999) through
// the E2B runtime proxy of base, the way the code-interpreter SDKs do with
// E2B_SANDBOX_URL=<base>/e2b/runtime.
type e2bInterp struct {
	base    string
	id      string
	access  string // envdAccessToken: the SDKs send it on /execute only
	traffic string // trafficAccessToken: sent on every call
}

// e2bCreateInterpSandbox creates a code-interpreter-v1 sandbox through E2B's
// v2 create (what e2b >= 2.51 calls), then reconnects through v2 connect,
// and checks both hand out the tokens the code-interpreter SDKs need.
func e2bCreateInterpSandbox(t *testing.T, ctx context.Context) e2bInterp {
	t.Helper()
	st, body := fcDo(t, ctx, http.MethodPost, "", "/e2b/v2/sandboxes", map[string]any{"templateID": "code-interpreter-v1", "timeout": 1200}, nil)
	if st != http.StatusCreated {
		t.Fatalf("E2B v2 create code-interpreter-v1 = %d, want 201; body=%s", st, body)
	}
	var created struct {
		SandboxID          string `json:"sandboxID"`
		EnvdAccessToken    string `json:"envdAccessToken"`
		TrafficAccessToken string `json:"trafficAccessToken"`
	}
	fcDecode(t, body, &created)
	if created.SandboxID == "" {
		t.Fatalf("E2B v2 create returned no sandboxID: %s", body)
	}
	destroySandbox(t, created.SandboxID)
	if created.EnvdAccessToken == "" || created.TrafficAccessToken == "" {
		t.Fatalf("a secure E2B sandbox came back without its tokens: %s", body)
	}
	// On a cluster the public address can land this call on a node that has
	// not yet seen the brand-new sandbox's placement, which answers 404 for
	// a moment (live: UC-712 on cluster-hetero-lite, 1 s after the create).
	// That catch-up window is the cluster's, not the facade's, so wait it
	// out briefly instead of failing the case.
	for deadline := time.Now().Add(30 * time.Second); ; {
		st, body = fcDo(t, ctx, http.MethodPost, "", "/e2b/v2/sandboxes/"+created.SandboxID+"/connect", map[string]any{"timeout": 1200}, nil)
		if st != http.StatusNotFound || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	var connected struct {
		SandboxID          string `json:"sandboxID"`
		TrafficAccessToken string `json:"trafficAccessToken"`
	}
	if st != http.StatusOK {
		t.Fatalf("E2B v2 connect = %d, want 200; body=%s", st, body)
	}
	fcDecode(t, body, &connected)
	if connected.SandboxID != created.SandboxID || connected.TrafficAccessToken != created.TrafficAccessToken {
		t.Fatalf("E2B v2 connect = %s, want the same sandbox and traffic token", body)
	}
	e := e2bInterp{base: sc.BaseURL, id: created.SandboxID, access: created.EnvdAccessToken, traffic: created.TrafficAccessToken}
	e.waitHealthy(t, ctx)
	return e
}

// request builds a call to the interpreter. access adds X-Access-Token, as
// the SDKs do on /execute only; contexts calls carry the traffic token
// alone, so they prove the proxy accepts it.
func (e e2bInterp) request(t *testing.T, ctx context.Context, method, path string, body any, access bool) *http.Request {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(e.base, "/")+"/e2b/runtime"+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("E2b-Sandbox-Id", e.id)
	req.Header.Set("E2b-Sandbox-Port", "49999")
	if e.traffic != "" {
		req.Header.Set("E2B-Traffic-Access-Token", e.traffic)
	}
	if access && e.access != "" {
		req.Header.Set("X-Access-Token", e.access)
	}
	return req
}

func (e e2bInterp) call(t *testing.T, ctx context.Context, method, path string, body any) (int, string) {
	t.Helper()
	resp, err := harness.HTTPClient(0).Do(e.request(t, ctx, method, path, body, false))
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// waitHealthy waits for the interpreter to answer: E2B's create returns
// before the agent in a fresh sandbox listens.
func (e e2bInterp) waitHealthy(t *testing.T, ctx context.Context) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		st, body := e.call(t, ctx, http.MethodGet, "/health", nil)
		if st == http.StatusOK {
			if strings.TrimSpace(body) != `"OK"` {
				t.Fatalf("GET /health = %q, want the JSON string \"OK\"", body)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the E2B interpreter of %s never answered /health (last %d %s)", e.id, st, body)
		}
		time.Sleep(2 * time.Second)
	}
}

// e2bLine is one NDJSON line of /execute with when it arrived.
type e2bLine struct {
	at     time.Time
	fields map[string]any
}

func (l e2bLine) kind() string { s, _ := l.fields["type"].(string); return s }

func (l e2bLine) str(key string) string { s, _ := l.fields[key].(string); return s }

// e2bRun is a finished /execute stream.
type e2bRun struct {
	status int
	body   string // the whole body when the status is not 200
	lines  []e2bLine
	ended  time.Time
}

func (r e2bRun) stdout() string {
	var b strings.Builder
	for _, l := range r.lines {
		if l.kind() == "stdout" {
			b.WriteString(l.str("text"))
		}
	}
	return b.String()
}

// mainText is the text of the run's main result, "" when there is none.
func (r e2bRun) mainText() string {
	for _, l := range r.lines {
		if l.kind() == "result" && l.fields["is_main_result"] == true {
			return l.str("text")
		}
	}
	return ""
}

func (r e2bRun) errorLine() (e2bLine, bool) {
	for _, l := range r.lines {
		if l.kind() == "error" {
			return l, true
		}
	}
	return e2bLine{}, false
}

func (r e2bRun) count() int {
	if len(r.lines) == 0 {
		return -1
	}
	n, _ := r.lines[0].fields["execution_count"].(float64)
	return int(n)
}

// execute posts body to /execute and reads the whole stream, checking the
// framing every E2B SDK relies on: no blank line (the JS SDK's JSON.parse
// throws on one), number_of_executions first, end_of_execution last and
// once, and a timestamp on every output line.
func (e e2bInterp) execute(t *testing.T, ctx context.Context, body map[string]any) e2bRun {
	t.Helper()
	resp, err := harness.HTTPClient(0).Do(e.request(t, ctx, http.MethodPost, "/execute", body, true))
	if err != nil {
		t.Fatalf("POST /execute: %v", err)
	}
	defer resp.Body.Close()
	run := e2bRun{status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		run.body = string(raw)
		return run
	}
	r := bufio.NewReader(resp.Body)
	for {
		raw, err := r.ReadBytes('\n')
		if len(raw) > 0 {
			if !bytes.HasSuffix(raw, []byte("\n")) {
				t.Fatalf("/execute ended inside a line: %q", raw)
			}
			text := bytes.TrimSuffix(raw, []byte("\n"))
			if len(bytes.TrimSpace(text)) == 0 {
				t.Fatalf("/execute sent a blank line after %d lines", len(run.lines))
			}
			var fields map[string]any
			if jerr := json.Unmarshal(text, &fields); jerr != nil {
				t.Fatalf("/execute line %q is not JSON: %v", text, jerr)
			}
			run.lines = append(run.lines, e2bLine{at: time.Now(), fields: fields})
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read /execute: %v", err)
		}
	}
	run.ended = time.Now()
	if len(run.lines) == 0 || run.lines[0].kind() != "number_of_executions" {
		t.Fatalf("the first /execute line is not number_of_executions: %v", run.lines)
	}
	if last := run.lines[len(run.lines)-1]; last.kind() != "end_of_execution" {
		t.Fatalf("the last /execute line is %v, want end_of_execution", last.fields)
	}
	for i, l := range run.lines {
		switch l.kind() {
		case "end_of_execution":
			if i != len(run.lines)-1 {
				t.Fatalf("end_of_execution at line %d of %d", i+1, len(run.lines))
			}
		case "stdout", "stderr":
			if l.str("timestamp") == "" {
				t.Fatalf("%s line without a timestamp: %v", l.kind(), l.fields)
			}
		}
	}
	return run
}

// mustExecute is execute with a 200 required.
func (e e2bInterp) mustExecute(t *testing.T, ctx context.Context, body map[string]any) e2bRun {
	t.Helper()
	run := e.execute(t, ctx, body)
	if run.status != http.StatusOK {
		t.Fatalf("POST /execute %v = %d %s", body, run.status, run.body)
	}
	return run
}

// e2bContext is one entry of GET /contexts.
type e2bContext struct {
	ID       string `json:"id"`
	Language string `json:"language"`
	Cwd      string `json:"cwd"`
}

func (e e2bInterp) contexts(t *testing.T, ctx context.Context) []e2bContext {
	t.Helper()
	st, body := e.call(t, ctx, http.MethodGet, "/contexts", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /contexts with only the traffic token = %d %s", st, body)
	}
	var out []e2bContext
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("GET /contexts = %q: %v", body, err)
	}
	return out
}

// checkStreamed fails unless the run's first stdout line arrived at least
// streamGap before the stream ended.
func (r e2bRun) checkStreamed(t *testing.T) {
	t.Helper()
	for _, l := range r.lines {
		if l.kind() == "stdout" {
			if gap := r.ended.Sub(l.at); gap < streamGap {
				t.Fatalf("the first stdout line arrived %v before the stream ended: held back, not streamed", gap)
			}
			return
		}
	}
	t.Fatalf("no stdout line in %v", r.lines)
}

// UC-711 — E2B's Code Interpreter wire through the E2B facade.
func TestCodeInterpE2BWire(t *testing.T) {
	harness.Require(t, sc, "UC-711")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	e := e2bCreateInterpSandbox(t, ctx)

	// A secure sandbox's interpreter is closed to a caller with no token.
	anon := e
	anon.access, anon.traffic = "", ""
	if run := anon.execute(t, ctx, map[string]any{"code": "1"}); run.status != http.StatusUnauthorized {
		t.Fatalf("/execute without a token = %d %s, want 401", run.status, run.body)
	}

	// The python and javascript defaults head the list, as on E2B.
	var defaultPython string
	languages := map[string]bool{}
	for _, c := range e.contexts(t, ctx) {
		languages[c.Language] = true
		if c.Language == "python" && defaultPython == "" {
			defaultPython = c.ID
			if c.Cwd != "/home/user" {
				t.Fatalf("the python default context's cwd = %q, want /home/user", c.Cwd)
			}
		}
	}
	if !languages["python"] || !languages["javascript"] {
		t.Fatalf("GET /contexts lists languages %v, want the python and javascript defaults", languages)
	}

	first := e.mustExecute(t, ctx, map[string]any{"code": "x = 1"})
	if l, bad := first.errorLine(); bad {
		t.Fatalf("x = 1 raised %v", l.fields)
	}
	second := e.mustExecute(t, ctx, map[string]any{"code": "print('a')\nx + 41"})
	if second.stdout() != "a\n" || second.mainText() != "42" {
		t.Fatalf("print('a'); x + 41: stdout %q, main result %q; lines %v", second.stdout(), second.mainText(), second.lines)
	}
	if second.count() <= first.count() {
		t.Fatalf("execution_count went %d then %d, want increasing", first.count(), second.count())
	}
	if run := e.mustExecute(t, ctx, map[string]any{"code": "'quoted'"}); run.mainText() != "quoted" {
		t.Fatalf("'quoted': main result %q, want the quotes stripped", run.mainText())
	}
	run := e.mustExecute(t, ctx, map[string]any{"code": "undefined_name"})
	if l, ok := run.errorLine(); !ok || l.str("name") != "NameError" || l.str("traceback") == "" {
		t.Fatalf("undefined_name: error line %v, want a NameError with a traceback", l.fields)
	}
	e.mustExecute(t, ctx, map[string]any{"code": streamingCode}).checkStreamed(t)

	envCode := "import os\nos.environ.get('UC711')"
	if run := e.mustExecute(t, ctx, map[string]any{"code": envCode, "env_vars": map[string]string{"UC711": "per-run"}}); run.mainText() != "per-run" {
		t.Fatalf("env_vars: main result %q", run.mainText())
	}
	if run := e.mustExecute(t, ctx, map[string]any{"code": envCode}); run.mainText() != "" {
		t.Fatalf("the env outlived its run: main result %q", run.mainText())
	}
	// The language picks that language's default context.
	if run := e.mustExecute(t, ctx, map[string]any{"code": "x", "language": "python"}); run.mainText() != "1" {
		t.Fatalf("language python: main result %q, want the default context's x", run.mainText())
	}
	if defaultPython != "" {
		if run := e.mustExecute(t, ctx, map[string]any{"code": "import os\nos.getcwd()", "context_id": defaultPython}); run.mainText() != "/home/user" {
			t.Fatalf("the default context's cwd: %q", run.mainText())
		}
	}

	st, body := e.call(t, ctx, http.MethodPost, "/contexts", map[string]any{"cwd": "/tmp"})
	var cc e2bContext
	if st != http.StatusOK || json.Unmarshal([]byte(body), &cc) != nil || cc.ID == "" || cc.Language != "python" || cc.Cwd != "/tmp" {
		t.Fatalf("POST /contexts = %d %s, want a python context in /tmp", st, body)
	}
	if run := e.mustExecute(t, ctx, map[string]any{"code": "q = 3\nimport os\nos.getcwd()", "context_id": cc.ID}); run.mainText() != "/tmp" {
		t.Fatalf("in the new context: cwd %q", run.mainText())
	}
	if run := e.execute(t, ctx, map[string]any{"code": "1", "context_id": cc.ID, "language": "python"}); run.status != http.StatusBadRequest ||
		!strings.Contains(run.body, "Only one of context_id or language can be provided") {
		t.Fatalf("context_id and language together = %d %q, want 400", run.status, run.body)
	}
	if st, body := e.call(t, ctx, http.MethodPost, "/contexts/"+cc.ID+"/restart", nil); st != http.StatusOK || strings.TrimSpace(body) != "null" {
		t.Fatalf("restart = %d %q, want 200 null", st, body)
	}
	run = e.mustExecute(t, ctx, map[string]any{"code": "q", "context_id": cc.ID})
	if l, ok := run.errorLine(); !ok || l.str("name") != "NameError" {
		t.Fatalf("after restart: error line %v, want NameError", l.fields)
	}
	if st, body := e.call(t, ctx, http.MethodDelete, "/contexts/"+cc.ID, nil); st != http.StatusOK || strings.TrimSpace(body) != "null" {
		t.Fatalf("delete = %d %q, want 200 null", st, body)
	}
	for _, c := range e.contexts(t, ctx) {
		if c.ID == cc.ID {
			t.Fatalf("a deleted context is still listed: %+v", c)
		}
	}
	if run := e.execute(t, ctx, map[string]any{"code": "1", "context_id": cc.ID}); run.status != http.StatusNotFound ||
		!strings.Contains(run.body, "Context "+cc.ID+" not found") {
		t.Fatalf("/execute in a deleted context = %d %q, want 404", run.status, run.body)
	}
	if st, body := e.call(t, ctx, http.MethodDelete, "/contexts/"+cc.ID, nil); st != http.StatusNotFound {
		t.Fatalf("a second delete = %d %q, want 404", st, body)
	}
}

// UC-712 — the interpreter driven from a node that does not own the sandbox:
// both streams are forwarded to the owner and stay live on the way.
func TestCodeInterpCrossNode(t *testing.T) {
	harness.Require(t, sc, "UC-712")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	e := e2bCreateInterpSandbox(t, ctx)
	other := nonOwnerAPI(t, c, e.id)

	remote, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: other, PATToken: sc.PAT, HTTPClient: harness.HTTPClient(0)})
	if err != nil {
		t.Fatalf("SDK client for %s: %v", other, err)
	}
	if _, err := remote.RunCode(ctx, e.id, "x = 7", sdktypes.RunCodeOptions{}); err != nil {
		t.Fatalf("RunCode through a non-owner: %v", err)
	}
	var chunks timedChunks
	exec, err := remote.RunCode(ctx, e.id, streamingCode+"\nx * 6", sdktypes.RunCodeOptions{OnStdout: chunks.add})
	ended := time.Now()
	if err != nil || exec.Text() != "42" || chunks.String() != "first\nsecond\n" {
		t.Fatalf("RunCode through a non-owner = %+v, %v; streamed %q", exec, err, chunks.String())
	}
	if at, _ := chunks.first(); ended.Sub(at) < streamGap {
		t.Fatalf("through the forward the first chunk arrived %v before the end: held back, not streamed", ended.Sub(at))
	}
	// The interrupt frame crosses the forward too.
	runCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	exec, err = remote.RunCode(runCtx, e.id, "import time\ntime.sleep(60)", sdktypes.RunCodeOptions{})
	stop()
	if err != nil || exec == nil || !exec.Interrupted {
		t.Fatalf("a cancelled run through a non-owner = %+v, %v; want Interrupted", exec, err)
	}
	if exec, err := remote.RunCode(ctx, e.id, "x", sdktypes.RunCodeOptions{}); err != nil || exec.Text() != "7" {
		t.Fatalf("after the interrupt through a non-owner: %+v, %v; want x kept", exec, err)
	}

	far := e
	far.base = other
	run := far.mustExecute(t, ctx, map[string]any{"code": streamingCode})
	if run.stdout() != "first\nsecond\n" {
		t.Fatalf("E2B /execute through a non-owner: stdout %q", run.stdout())
	}
	run.checkStreamed(t)
}

// langStep is one run of a language case: code, and the text that run's
// main result or stdout must contain ("" when the run only sets state).
type langStep struct{ code, want string }

// langHint explains a language failure in terms of what the deployment
// lacks, so a red row reads as "drivers not deployed yet" rather than as a
// mystery.
func langHint(lang, image string) string {
	return fmt.Sprintf("the %s driver ships with the code interpreter language drivers (feat/codeinterp-langs); a deployment whose toolboxd predates them answers an unsupported language, and an image without the interpreter answers InterpreterNotFound (image %s)", lang, image)
}

// interpLanguage runs steps in lang's default context of a fresh sandbox
// from image. Later steps read what earlier ones set, so a pass proves the
// context kept its state.
func interpLanguage(t *testing.T, lang, image string, steps []langStep) {
	t.Helper()
	interpLanguageCmd(t, lang, image, nil, steps)
}

// interpLanguageCmd is interpLanguage with cmd as the sandbox's main program.
func interpLanguageCmd(t *testing.T, lang, image string, cmd []string, steps []langStep) {
	t.Helper()
	sb := interpSandboxCmd(t, "docker", image, cmd)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, step := range steps {
		var streamed strings.Builder
		var mu sync.Mutex
		exec, err := sb.RunCode(ctx, step.code, sdktypes.RunCodeOptions{Language: lang, OnStdout: func(s string) {
			mu.Lock()
			streamed.WriteString(s)
			mu.Unlock()
		}})
		if err != nil {
			t.Fatalf("%s: RunCode(%q) failed: %v\n%s", lang, step.code, err, langHint(lang, image))
		}
		if exec.Error != nil {
			t.Fatalf("%s: RunCode(%q) raised %s: %s\n%s\n%s", lang, step.code, exec.Error.Name, exec.Error.Value, exec.Error.Traceback, langHint(lang, image))
		}
		// R shows each visible value as a display result, not the main one
		// (as E2B's R kernel does), so look at every result's text.
		got := exec.Text() + "\n" + interpStdout(exec)
		for _, r := range exec.Results {
			got += "\n" + r.Text
		}
		if step.want != "" && !strings.Contains(got, step.want) {
			t.Fatalf("%s: RunCode(%q) produced result %q and stdout %q, want %q in them", lang, step.code, exec.Text(), interpStdout(exec), step.want)
		}
		mu.Lock()
		if streamed.String() != interpStdout(exec) {
			t.Fatalf("%s: OnStdout got %q but Logs.Stdout is %q", lang, streamed.String(), interpStdout(exec))
		}
		mu.Unlock()
	}
}

// UC-713 — javascript on node:22-slim.
func TestCodeInterpLangJavaScript(t *testing.T) {
	harness.Require(t, sc, "UC-713")
	interpLanguage(t, "javascript", "node:22-slim", []langStep{
		{code: "let j = 20", want: ""},
		{code: "j + 1", want: "21"},
		{code: "console.log('js-' + (j * 2))", want: "js-40"},
	})
}

// UC-714 — typescript on node:22-slim (type stripping needs Node >= 22.13).
func TestCodeInterpLangTypeScript(t *testing.T) {
	harness.Require(t, sc, "UC-714")
	interpLanguage(t, "typescript", "node:22-slim", []langStep{
		{code: "let tsv: number = 7", want: ""},
		{code: "const doubled: number = tsv * 6\ndoubled", want: "42"},
	})
}

// UC-715 — bash on python:3.12-slim (Debian, so bash is there).
func TestCodeInterpLangBash(t *testing.T) {
	harness.Require(t, sc, "UC-715")
	interpLanguage(t, "bash", interpImage, []langStep{
		{code: "N=41", want: ""},
		{code: "echo $((N + 1))", want: "42"},
	})
}

// UC-716 — R on r-base.
func TestCodeInterpLangR(t *testing.T) {
	harness.Require(t, sc, "UC-716")
	// r-base's own command is `R`, which exits at once with an error when it
	// has no terminal ("you must specify '--save', ..."), and a sandbox ends
	// with its main program: the run then lost its connection (close 1006).
	// Keep the sandbox up with a command that does not exit.
	interpLanguageCmd(t, "r", "r-base:latest", []string{"sleep", "infinity"}, []langStep{
		{code: "x <- 41", want: ""},
		{code: "x + 1", want: "42"},
	})
}

// UC-717 — Java (jshell) on eclipse-temurin:21-jdk.
func TestCodeInterpLangJava(t *testing.T) {
	harness.Require(t, sc, "UC-717")
	interpLanguage(t, "java", "eclipse-temurin:21-jdk", []langStep{
		{code: "int k = 6;", want: ""},
		{code: "k * 7", want: "42"},
	})
}
