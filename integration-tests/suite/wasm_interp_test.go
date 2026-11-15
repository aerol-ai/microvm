//go:build integration

package suite

// Live checks for streamed commands, code-run, sessions, the code
// interpreter and several exposed ports on WASM sandboxes
// (plans/code-interpreter.md section 5). UC-724 and UC-725 cover what this
// stack ships first (W1..W3, #535). UC-726..728 cover W4..W6, which land
// later in the stack: against a deployment without them they fail, and the
// failure names the missing step rather than leaving a bare 501.

import (
	"bytes"
	"context"
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

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
	daytonasdk "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	daytonaoptions "github.com/daytonaio/daytona/libs/sdk-go/pkg/options"
	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

// wasmPythonSandbox creates a WASM sandbox on the staged python module
// (python.wasm: CPython for WASI) and waits until it has started.
func wasmPythonSandbox(t *testing.T) *microvm.Sandbox {
	t.Helper()
	c := client(t)
	ref := stagedWasmModuleRefOrDefault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t), Runtime: "wasm", Image: ref, ModuleRef: ref,
	})
	if err != nil {
		t.Fatalf("create a WASM sandbox on %q: %v", ref, err)
	}
	t.Cleanup(func() { destroyBest(c, sb.ID) })
	waitRunning(t, sb)
	return sb
}

// byteChunks collects streamed output with the arrival time of the first
// chunk.
type byteChunks struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	first time.Time
}

func (b *byteChunks) add(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() == 0 {
		b.first = time.Now()
	}
	b.buf.Write(p)
}

func (b *byteChunks) snapshot() (string, time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String(), b.first
}

// wasiBusyWait spends n seconds in a one-line python expression. time.sleep
// does not work in python.wasm under wazero (CPython's clock_nanosleep asks
// for an absolute deadline, which wazero's poll_oneoff refuses with ENOTSUP),
// and a one-liner keeps the -c argument free of newlines.
func wasiBusyWait(n int) string {
	return fmt.Sprintf("t = time.time(); all(iter(lambda: time.time() - t < %d, False))", n)
}

// UC-724 — streamed exec on WASM with the Go SDK. The WASM agent may not
// list exec.argv, so this uses the command form: the host splits it into
// words with shell quoting and no expansion, and python runs inside the
// sandbox's worker.
func TestWasmInterpExecStream(t *testing.T) {
	harness.Require(t, sc, "UC-724")
	sb := wasmPythonSandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	var out, errOut byteChunks
	h, err := sb.ExecStream(ctx, sdktypes.ExecStreamOptions{
		Command: `python -c "import sys, time; print('out-724', flush=True); print('err-724', file=sys.stderr, flush=True); ` +
			wasiBusyWait(4) + `; print('late-724'); sys.exit(3)"`,
		OnStdout: out.add,
		OnStderr: errOut.add,
	})
	if err != nil {
		t.Fatalf("ExecStream on WASM: %v", err)
	}
	info, err := h.Wait()
	ended := time.Now()
	stdout, firstOut := out.snapshot()
	stderr, _ := errOut.snapshot()
	if err != nil {
		t.Fatalf("ExecStream on WASM ended with %v (stdout %q, stderr %q)", err, stdout, stderr)
	}
	if info.Code != 3 || stdout != "out-724\nlate-724\n" || stderr != "err-724\n" {
		t.Fatalf("exit %+v, stdout %q, stderr %q; want exit 3 and the two streams apart", info, stdout, stderr)
	}
	if gap := ended.Sub(firstOut); gap < streamGap {
		t.Fatalf("the first stdout chunk arrived %v before the exit: held back, not streamed", gap)
	}

	// stdin: what the client writes reaches python; closing it is EOF.
	var echoed byteChunks
	h, err = sb.ExecStream(ctx, sdktypes.ExecStreamOptions{
		Command:  `python -c "import sys; print(sys.stdin.read().strip().upper())"`,
		OnStdout: echoed.add,
	})
	if err != nil {
		t.Fatalf("ExecStream with stdin on WASM: %v", err)
	}
	if err := h.WriteString("hello wasm\n"); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	info, err = h.Wait()
	got, _ := echoed.snapshot()
	if err != nil || info.Code != 0 || got != "HELLO WASM\n" {
		t.Fatalf("stdin run: exit %+v, %v, stdout %q; want HELLO WASM", info, err, got)
	}
}

// daytonaClient is the pinned Daytona Go SDK pointed at the facade.
func daytonaClient(t *testing.T) *daytonasdk.Client {
	t.Helper()
	dc, err := daytonasdk.NewClientWithConfig(&daytonatypes.DaytonaConfig{
		APIKey: sc.PAT,
		APIUrl: strings.TrimRight(sc.BaseURL, "/") + "/daytona",
	})
	if err != nil {
		t.Fatalf("Daytona SDK client: %v", err)
	}
	t.Cleanup(func() { _ = dc.Close(context.Background()) })
	return dc
}

// daytonaWasmSandbox creates a WASM python sandbox the way a Daytona user
// does: labels runtime=wasm and module_ref=<module>, which the facade turns
// into a native WASM create (facadeutil.TranslateWasmCreate). It returns the
// sandbox opened with the Daytona Go SDK.
func daytonaWasmSandbox(t *testing.T, ctx context.Context) *daytonasdk.Sandbox {
	t.Helper()
	ref := stagedWasmModuleRefOrDefault(t)
	st, body := fcDo(t, ctx, http.MethodPost, "", "/daytona/sandbox", map[string]any{
		"labels": map[string]string{"runtime": "wasm", "module_ref": ref},
	}, nil)
	if st != http.StatusOK {
		t.Fatalf("Daytona create with labels runtime=wasm module_ref=%s = %d; body=%s", ref, st, body)
	}
	var r idResponse
	fcDecode(t, body, &r)
	if r.ID == "" {
		t.Fatalf("Daytona create returned no id: %s", body)
	}
	destroySandbox(t, r.ID)
	got, err := client(t).SDK().Get(ctx, r.ID)
	if err != nil {
		t.Fatalf("get %s: %v", r.ID, err)
	}
	if got.Runtime != "wasm" {
		t.Fatalf("the Daytona create made a %q sandbox, want wasm", got.Runtime)
	}
	interpWaitStarted(t, got, 3*time.Minute)
	dsb, err := daytonaClient(t).Get(ctx, r.ID)
	if err != nil {
		t.Fatalf("Daytona SDK Get(%s): %v", r.ID, err)
	}
	return dsb
}

// UC-725 — Daytona process.codeRun on WASM.
func TestWasmInterpDaytonaCodeRun(t *testing.T) {
	harness.Require(t, sc, "UC-725")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dsb := daytonaWasmSandbox(t, ctx)

	res, err := dsb.Process.CodeRun(ctx, "print(6 * 7)")
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Result) != "42" {
		t.Fatalf("codeRun print(6 * 7) on WASM = %+v, %v; want exit 0 and 42", res, err)
	}
	res, err = dsb.Process.CodeRun(ctx, "import sys\nprint('bye')\nsys.exit(3)")
	if err != nil || res.ExitCode != 3 || strings.TrimSpace(res.Result) != "bye" {
		t.Fatalf("codeRun sys.exit(3) on WASM = %+v, %v; want exit 3 and its output", res, err)
	}
	res, err = dsb.Process.CodeRun(ctx, "import os\nprint(os.environ.get('UC725'))",
		daytonaoptions.WithCodeRunParams(daytonatypes.CodeRunParams{Env: map[string]string{"UC725": "on-wasm"}}))
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Result) != "on-wasm" {
		t.Fatalf("codeRun with envs on WASM = %+v, %v", res, err)
	}
}

// laterStepHint names the plan step a WASM failure is waiting for.
func laterStepHint(step string) string {
	return "this lands later in the stack (" + step + ", plans/code-interpreter.md section 5); a deployment without it answers 501 or an unsupported feature"
}

// UC-726 — Daytona sessions on WASM (W4).
func TestWasmInterpDaytonaSessions(t *testing.T) {
	harness.Require(t, sc, "UC-726")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dsb := daytonaWasmSandbox(t, ctx)
	hint := laterStepHint("W4, Daytona sessions on WASM, #178")

	const session = "uc726"
	if err := dsb.Process.CreateSession(ctx, session); err != nil {
		t.Fatalf("CreateSession on WASM: %v\n%s", err, hint)
	}
	t.Cleanup(func() { _ = dsb.Process.DeleteSession(context.Background(), session) })

	// Runs in one session share /work: the second reads what the first wrote.
	wrote, err := dsb.Process.ExecuteSessionCommand(ctx, session, `python -c "open('/work/uc726.txt', 'w').write('42')"`, false, false)
	if err != nil {
		t.Fatalf("session command on WASM: %v\n%s", err, hint)
	}
	if fmt.Sprint(wrote["exitCode"]) != "0" {
		t.Fatalf("the writing command = %v, want exit 0", wrote)
	}
	read, err := dsb.Process.ExecuteSessionCommand(ctx, session, `python -c "print(open('/work/uc726.txt').read())"`, false, false)
	if err != nil || fmt.Sprint(read["exitCode"]) != "0" || strings.TrimSpace(fmt.Sprint(read["stdout"])) != "42" {
		t.Fatalf("the reading command = %v, %v; want exit 0 and 42", read, err)
	}

	// An async command: its id comes back at once and its logs fill in.
	started, err := dsb.Process.ExecuteSessionCommand(ctx, session, `python -c "import time; print('a', flush=True); `+wasiBusyWait(1)+`; print('b')"`, true, false)
	if err != nil {
		t.Fatalf("async session command on WASM: %v", err)
	}
	cmdID, _ := started["id"].(string)
	if cmdID == "" {
		t.Fatalf("the async command returned no id: %v", started)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		cmd, err := dsb.Process.GetSessionCommand(ctx, session, cmdID)
		if err != nil {
			t.Fatalf("GetSessionCommand: %v", err)
		}
		if code, done := cmd["exitCode"]; done {
			if fmt.Sprint(code) != "0" {
				t.Fatalf("the async command = %v, want exit 0", cmd)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the async command never finished: %v", cmd)
		}
		time.Sleep(time.Second)
	}
	logs, err := dsb.Process.GetSessionCommandLogs(ctx, session, cmdID)
	if err != nil {
		t.Fatalf("GetSessionCommandLogs: %v", err)
	}
	if out := logs.GetStdout(); !strings.Contains(out, "a\nb") {
		t.Fatalf("the async command's stdout log = %q, want a then b", out)
	}
	if err := dsb.Process.DeleteSession(ctx, session); err != nil {
		t.Fatalf("DeleteSession on WASM: %v", err)
	}
}

// UC-727 — the Go SDK code interpreter on WASM (W5): python contexts run in
// python.wasm inside the sandbox's own worker.
func TestWasmInterpRunCode(t *testing.T) {
	harness.Require(t, sc, "UC-727")
	sb := wasmPythonSandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	hint := laterStepHint("W5, the code interpreter on WASM")

	run := func(code string, opts sdktypes.RunCodeOptions) *sdktypes.Execution {
		t.Helper()
		exec, err := sb.RunCode(ctx, code, opts)
		if err != nil {
			if errors.Is(err, microvm.ErrUnsupportedFeature) {
				t.Fatalf("RunCode(%q) on WASM: %v\n%s", code, err, hint)
			}
			t.Fatalf("RunCode(%q) on WASM: %v", code, err)
		}
		return exec
	}
	run("x = 5", sdktypes.RunCodeOptions{})
	if exec := run("print(x)\nx * 2", sdktypes.RunCodeOptions{}); exec.Text() != "10" || interpStdout(exec) != "5\n" {
		t.Fatalf("state on WASM: result %q, stdout %q, error %+v", exec.Text(), interpStdout(exec), exec.Error)
	}
	if exec := run("1/0", sdktypes.RunCodeOptions{}); exec.Error == nil || exec.Error.Name != "ZeroDivisionError" {
		t.Fatalf("exception on WASM: %+v", exec.Error)
	}

	cc, err := sb.CreateCodeContext(ctx, sdktypes.CodeContextOptions{})
	if err != nil {
		t.Fatalf("CreateCodeContext on WASM: %v\n%s", err, hint)
	}
	on := sdktypes.RunCodeOptions{ContextID: cc.ID}
	run("y = 'own'", on)
	if exec := run("print(y, 'x' in globals())", on); interpStdout(exec) != "own False\n" {
		t.Fatalf("a second WASM context: stdout %q (error %+v)", interpStdout(exec), exec.Error)
	}
	list, err := sb.ListCodeContexts(ctx)
	if err != nil || !hasCodeContext(list, cc.ID) {
		t.Fatalf("ListCodeContexts on WASM = %+v, %v", list, err)
	}

	// WASM has no signals: a timeout stops the instance (D12). The context
	// must still answer afterwards.
	two := 2
	if _, err := sb.RunCode(ctx, "while True:\n    pass", sdktypes.RunCodeOptions{ContextID: cc.ID, TimeoutSeconds: &two}); !errors.Is(err, microvm.ErrCodeRunTimeout) {
		t.Fatalf("a busy loop past its 2 s timeout on WASM returned %v, want ErrCodeRunTimeout", err)
	}
	if exec := run("print('after')", on); interpStdout(exec) != "after\n" {
		t.Fatalf("after the timeout on WASM: stdout %q (error %+v)", interpStdout(exec), exec.Error)
	}
	if err := sb.DeleteCodeContext(ctx, cc.ID); err != nil {
		t.Fatalf("DeleteCodeContext on WASM: %v", err)
	}
	if list, err := sb.ListCodeContexts(ctx); err != nil || hasCodeContext(list, cc.ID) {
		t.Fatalf("after delete on WASM: %+v, %v", list, err)
	}
}

// buildWasmPortsGuest compiles testdata/wasmports for wasip1 into a temp
// folder; the test runs in the suite's package folder, so the source is a
// relative path.
func buildWasmPortsGuest(t *testing.T) []byte {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain to build the WASM guest: %v", err)
	}
	out := filepath.Join(t.TempDir(), "wasmports.wasm")
	cmd := exec.Command(gobin, "build", "-trimpath", "-o", out, "./testdata/wasmports")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the wasip1 guest: %v\n%s", err, b)
	}
	module, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return module
}

// previewBody GETs url until it answers 200 (routing, DNS and TLS can lag the
// expose call) and returns the body.
func previewBody(t *testing.T, url string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			cancel()
			if resp.StatusCode == http.StatusOK {
				return string(body)
			}
			last = fmt.Sprintf("%d %s", resp.StatusCode, body)
		} else {
			cancel()
			last = err.Error()
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("%s never answered 200 (last: %s)", url, last)
	return ""
}

// UC-728 — two exposed ports on one WASM guest (#177, W6). The guest
// (testdata/wasmports) serves every listener the engine pre-opens and
// answers "port=<P>"; it is built here and pushed through the module API,
// which needs registry credentials the scenario does not carry by itself.
func TestWasmInterpTwoPorts(t *testing.T) {
	harness.Require(t, sc, "UC-728")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	// AEROL_WASM_TWOPORT_MODULE names a copy of the guest already on the
	// node (a bare file name in its modules dir, staged with
	// scripts/stage-to-node.sh; the operator PAT may use host module refs).
	// Without it the guest is pushed through the module API, which needs
	// registry credentials the scenario does not carry by itself.
	moduleRef := os.Getenv("AEROL_WASM_TWOPORT_MODULE")
	if moduleRef != "" {
		// In cluster mode placement only picks workers for a module the
		// catalogue knows, so register the staged file first (live:
		// single-node-wasm answered "no worker placement target" without
		// it). A repeat registration of the same ref is fine to ignore.
		if _, err := c.SDK().CreateWasmModule(ctx, sdktypes.CreateWasmModuleOptions{ModuleRef: moduleRef}); err != nil {
			t.Logf("register %s: %v (continuing: it may already be registered)", moduleRef, err)
		}
	}
	if moduleRef == "" {
		user := os.Getenv("AEROL_WASM_REGISTRY_USER")
		token := os.Getenv("AEROL_WASM_REGISTRY_TOKEN")
		if user == "" || token == "" {
			t.Skip("set AEROL_WASM_TWOPORT_MODULE (a guest staged on the node), or AEROL_WASM_REGISTRY_USER / AEROL_WASM_REGISTRY_TOKEN to push it through POST /v1/wasm-modules/push (as UC-52)")
		}
		module := buildWasmPortsGuest(t)
		pushed, err := c.SDK().PushWasmModule(ctx, sdktypes.PushWasmModuleOptions{
			Name: "aerol-itest-wasmports", Tag: fmt.Sprintf("uc728-%d", time.Now().Unix()),
			Module: module, RegistryUsername: user, RegistryToken: token,
		})
		if err != nil || pushed.ModuleRef == "" {
			t.Fatalf("push the two-port guest: %+v, %v", pushed, err)
		}
		moduleRef = pushed.ModuleRef
	}
	public := true
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t), Runtime: "wasm", Image: moduleRef, ModuleRef: moduleRef, AllowPublicTraffic: &public,
	})
	if err != nil {
		t.Fatalf("create a WASM sandbox on %s: %v", moduleRef, err)
	}
	t.Cleanup(func() { destroyBest(c, sb.ID) })
	waitRunning(t, sb)

	bodies := map[int]string{}
	for _, port := range []int{8080, 9090} {
		res, err := sb.ExposePort(ctx, port)
		if err != nil || res.PublicURL == "" {
			t.Fatalf("expose %d on WASM: %+v, %v", port, res, err)
		}
		bodies[port] = strings.TrimSpace(previewBody(t, res.PublicURL))
	}
	// Re-read the first port after the second expose: adding a listener
	// re-instantiates the guest, and the first route must still reach its
	// own listener.
	if again, err := sb.ExposePort(ctx, 8080); err != nil {
		t.Fatalf("expose 8080 again: %v", err)
	} else {
		bodies[8080] = strings.TrimSpace(previewBody(t, again.PublicURL))
	}
	if bodies[8080] != "port=8080" || bodies[9090] != "port=9090" {
		t.Fatalf("bodies %v, want port=8080 and port=9090 from one guest\n%s", bodies,
			laterStepHint("W6, several exposed ports on one WASM guest, #177; a guest that answers port=unknown ran on an engine without AEROL_WASM_LISTEN_FDS"))
	}
}
