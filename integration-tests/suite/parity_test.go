//go:build integration

package suite

// Live checks for plans/agent-sandbox-feature-parity.md. Each use case maps
// to one plan item; the parity scenario runs them all together.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// daytonaToolbox calls a Daytona toolbox route on a sandbox through the live
// /daytona facade.
func daytonaToolbox(t *testing.T, ctx context.Context, method, sandboxID, path string, query url.Values, body any) (int, []byte) {
	t.Helper()
	full := "/daytona/toolbox/" + sandboxID + path
	if len(query) > 0 {
		full += "?" + query.Encode()
	}
	return fcDo(t, ctx, method, "", full, body, nil)
}

func paritySandbox(t *testing.T) *microvm.Sandbox {
	t.Helper()
	sb := client(t).NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	return sb
}

func parityExec(t *testing.T, ctx context.Context, sb *microvm.Sandbox, command string) string {
	t.Helper()
	res, err := sb.ExecCommand(ctx, command)
	if err != nil {
		t.Fatalf("exec %q: %v", command, err)
	}
	return strings.TrimSpace(res.Stdout)
}

// UC-369 — Daytona SDK file calls that used to 404 now work live (plan B1):
// create a folder with a mode, replace text in a file, set permissions, and
// delete (a folder only with recursive=true). Language servers answer a
// clear 501, not 404 (Daytona terminals work since E8: parity_pty_test.go).
func TestParityDaytonaFileCallsLive(t *testing.T) {
	harness.Require(t, sc, "UC-369")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	folder := "/tmp/uc369/a/b"
	if st, body := daytonaToolbox(t, ctx, http.MethodPost, sb.ID, "/files/folder", url.Values{"path": {folder}, "mode": {"750"}}, nil); st/100 != 2 {
		t.Fatalf("createFolder = %d %s", st, body)
	}
	if got := parityExec(t, ctx, sb, "stat -c %a "+folder); got != "750" {
		t.Fatalf("folder mode = %q, want 750", got)
	}

	file := "/tmp/uc369/f.txt"
	if err := sb.UploadFile(ctx, file, []byte("a.b.c x a.b.c")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	st, body := daytonaToolbox(t, ctx, http.MethodPost, sb.ID, "/files/replace", nil, map[string]any{
		"files": []string{file, "/tmp/uc369/missing.txt"}, "pattern": "a.b.c", "newValue": "Z",
	})
	if st != http.StatusOK {
		t.Fatalf("replaceInFiles = %d %s", st, body)
	}
	var results []struct {
		File    string `json:"file"`
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &results); err != nil || len(results) != 2 || !results[0].Success || results[1].Success || results[1].Error == "" {
		t.Fatalf("replace results = %s (err %v)", body, err)
	}
	if got := parityExec(t, ctx, sb, "cat "+file); got != "Z x Z" {
		t.Fatalf("replaced content = %q, want plain-text replace %q", got, "Z x Z")
	}

	if st, body := daytonaToolbox(t, ctx, http.MethodPost, sb.ID, "/files/permissions", url.Values{"path": {file}, "mode": {"600"}}, nil); st/100 != 2 {
		t.Fatalf("setFilePermissions = %d %s", st, body)
	}
	if got := parityExec(t, ctx, sb, "stat -c %a "+file); got != "600" {
		t.Fatalf("file mode = %q, want 600", got)
	}

	if st, _ := daytonaToolbox(t, ctx, http.MethodDelete, sb.ID, "/files", url.Values{"path": {"/tmp/uc369/a"}}, nil); st != http.StatusConflict {
		t.Fatalf("deleteFile(folder) without recursive = %d, want 409", st)
	}
	if st, body := daytonaToolbox(t, ctx, http.MethodDelete, sb.ID, "/files", url.Values{"path": {"/tmp/uc369/a"}, "recursive": {"true"}}, nil); st/100 != 2 {
		t.Fatalf("deleteFile(recursive) = %d %s", st, body)
	}
	if got := parityExec(t, ctx, sb, "test -e /tmp/uc369/a && echo present || echo gone"); got != "gone" {
		t.Fatalf("folder after delete: %s", got)
	}

	for _, probe := range []struct{ method, path, want string }{
		{http.MethodPost, "/lsp/start", "language servers"},
	} {
		st, body := daytonaToolbox(t, ctx, probe.method, sb.ID, probe.path, nil, map[string]any{})
		if st != http.StatusNotImplemented || !strings.Contains(string(body), probe.want) {
			t.Fatalf("%s %s = %d %s, want a clear 501", probe.method, probe.path, st, body)
		}
	}
}

// assertExecReturnsWithBackgroundJob is plan B2: a command that starts a
// background job returns when the command itself ends and the job keeps
// running; a timeout stops the whole process group and says timed_out.
func assertExecReturnsWithBackgroundJob(t *testing.T, sb *microvm.Sandbox) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	start := time.Now()
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{Command: "sleep 120 >/dev/null 2>&1 </dev/null & sleep 120 & echo $!", TimeoutSeconds: 60})
	if err != nil {
		t.Fatalf("exec with a background job: %v", err)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("exec took %v; it waited for the background job", took)
	}
	pid := strings.TrimSpace(res.Stdout)
	if res.ExitCode != 0 || res.TimedOut || pid == "" {
		t.Fatalf("result = %+v", res)
	}
	if got := parityExec(t, ctx, sb, "kill -0 "+pid+" && echo alive || echo gone"); got != "alive" {
		t.Fatalf("background job %s after exec returned: %s, want alive", pid, got)
	}
	_ = parityExec(t, ctx, sb, "kill "+pid+" 2>/dev/null; echo done")

	start = time.Now()
	res, err = sb.Exec(ctx, sdktypes.ExecRequest{Command: "sleep 120 & echo $!; sleep 120", TimeoutSeconds: 3})
	if err != nil {
		t.Fatalf("exec that times out: %v", err)
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("timed-out exec took %v", took)
	}
	if !res.TimedOut {
		t.Fatalf("timed_out not set: %+v", res)
	}
	pid = strings.TrimSpace(res.Stdout)
	deadline := time.Now().Add(20 * time.Second)
	for {
		got := parityExec(t, ctx, sb, "kill -0 "+pid+" 2>/dev/null && echo alive || echo gone")
		if got == "gone" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background job %s survived the timeout", pid)
		}
		time.Sleep(time.Second)
	}

	// Daytona executeCommand shares the handler (eng review ER2).
	start = time.Now()
	st, body := daytonaToolbox(t, ctx, http.MethodPost, sb.ID, "/process/execute", nil, map[string]any{"command": "sh -c 'sleep 120 & echo daytona-started'", "timeout": 60})
	if st != http.StatusOK || !strings.Contains(string(body), "daytona-started") {
		t.Fatalf("Daytona executeCommand = %d %s", st, body)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("Daytona executeCommand took %v; it waited for the background job", took)
	}
	_ = parityExec(t, ctx, sb, "pkill -f 'sleep 120' 2>/dev/null; echo done")
}

// UC-370 — exec returns when the command ends, with background jobs kept
// running and timeouts stopping the whole group, via v1 and Daytona.
func TestParityExecReturnsWithBackgroundJob(t *testing.T) {
	harness.Require(t, sc, "UC-370")
	assertExecReturnsWithBackgroundJob(t, paritySandbox(t))
}

// UC-371 — the same on gVisor, where the reaper reports ESRCH (UC-335).
func TestParityExecReturnsWithBackgroundJobGvisor(t *testing.T) {
	harness.Require(t, sc, "UC-371")
	sb := client(t).NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Runtime: "gvisor"})
	waitRunning(t, sb)
	assertExecReturnsWithBackgroundJob(t, sb)
}

// UC-372 — sandboxd counts toolbox calls by API, feature and result (plan
// O4): a Daytona language-server call shows as daytona/lsp/501 and a v1
// exec as v1/exec/2xx, summed over every node.
func TestParityToolboxCallCounter(t *testing.T) {
	harness.Require(t, sc, "UC-372")
	targets := harness.LoadIntegrationTargets()
	bases := map[string]string{}
	for _, node := range targets.Nodes {
		bases[node.Name] = nodeBase(t, node)
	}
	sum := func(labels map[string]string) float64 {
		total := 0.0
		for _, base := range bases {
			total += harness.MetricValueOrZero(nodeMetrics(t, base), "aerolvm_toolbox_calls_total", labels)
		}
		return total
	}
	lspLabels := map[string]string{"key": "daytona", "key2": "lsp", "key3": "501"}
	execLabels := map[string]string{"key": "v1", "key2": "exec", "key3": "2xx"}
	lspBefore, execBefore := sum(lspLabels), sum(execLabels)

	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if st, body := daytonaToolbox(t, ctx, http.MethodPost, sb.ID, "/lsp/start", nil, map[string]any{}); st != http.StatusNotImplemented {
		t.Fatalf("lsp/start = %d %s, want 501", st, body)
	}
	if _, err := sb.ExecCommand(ctx, "true"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		lsp, exec := sum(lspLabels), sum(execLabels)
		if lsp >= lspBefore+1 && exec >= execBefore+1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("toolbox call counter: daytona/lsp/501 %v -> %v, v1/exec/2xx %v -> %v", lspBefore, lsp, execBefore, exec)
		}
		time.Sleep(2 * time.Second)
	}
}
