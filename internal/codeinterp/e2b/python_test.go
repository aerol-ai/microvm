package e2b

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/proc"
)

// TestRealPythonKernel drives the handler against python3 through the
// process launcher, end to end. It skips where python3 is missing, and
// while the launcher is still the stub.
func TestRealPythonKernel(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	l := proc.New(proc.Config{Env: os.Environ, DriverDir: t.TempDir()})
	probe, err := l.Launch(context.Background(), codeinterp.Spec{Language: codeinterp.LangPython, Cwd: t.TempDir()})
	if err != nil {
		if strings.Contains(err.Error(), "not implemented") {
			t.Skip("the process launcher is not built yet")
		}
		t.Fatal(err)
	}
	_ = probe.Close()

	// os.getcwd() reports the resolved path (macOS temp dirs sit behind a symlink).
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := codeinterp.NewManager(managerOptions(l, nil, home, os.MkdirAll, os.Getwd))
	t.Cleanup(m.Close)
	e := &testEnv{m: m, h: newHandler(m, nil, KeepaliveInterval)}

	run := func(body string) []map[string]any {
		t.Helper()
		rec := e.do(http.MethodPost, "/execute", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
		var out []map[string]any
		for _, line := range splitLines(t, rec.Body.String()) {
			var v map[string]any
			if err := json.Unmarshal([]byte(line), &v); err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		if last := out[len(out)-1]; last["type"] != "end_of_execution" {
			t.Fatalf("%s: last line %v", body, last)
		}
		return out
	}
	find := func(lines []map[string]any, typ string) map[string]any {
		for _, l := range lines {
			if l["type"] == typ {
				return l
			}
		}
		return nil
	}

	run(`{"code":"x = 6 * 7"}`)
	if r := find(run(`{"code":"x"}`), "result"); r == nil || r["text"] != "42" || r["is_main_result"] != true {
		t.Fatalf("state did not survive between runs: %v", r)
	}
	if r := find(run(`{"code":"'abc'"}`), "result"); r == nil || r["text"] != "abc" {
		t.Fatalf("string result: %v", r)
	}
	if o := find(run(`{"code":"print('hi')"}`), "stdout"); o == nil || o["text"] != "hi\n" {
		t.Fatalf("stdout: %v", o)
	}
	if er := find(run(`{"code":"1/0"}`), "error"); er == nil || er["name"] != "ZeroDivisionError" {
		t.Fatalf("error: %v", er)
	}
	if r := find(run(`{"code":"import os; os.getcwd()"}`), "result"); r == nil || r["text"] != home {
		t.Fatalf("cwd: %v, want %s", r, home)
	}
	if o := find(run(`{"code":"import os; print(os.environ.get('K'))","env_vars":{"K":"v"}}`), "stdout"); o == nil || o["text"] != "v\n" {
		t.Fatalf("env: %v", o)
	}
}
