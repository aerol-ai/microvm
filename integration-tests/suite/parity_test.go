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
// delete (a folder only with recursive=true). Language servers and Daytona
// terminals answer a clear 501, not 404.
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
		{http.MethodPost, "/process/pty", "terminals"},
	} {
		st, body := daytonaToolbox(t, ctx, probe.method, sb.ID, probe.path, nil, map[string]any{})
		if st != http.StatusNotImplemented || !strings.Contains(string(body), probe.want) {
			t.Fatalf("%s %s = %d %s, want a clear 501", probe.method, probe.path, st, body)
		}
	}
}
