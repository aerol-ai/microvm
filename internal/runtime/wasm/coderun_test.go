package wasm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestCodeRunArgs(t *testing.T) {
	cases := []struct {
		family string
		argv   []string
		want   string
	}{
		{"python", nil, "python|-c|print(1)"},
		// CPython's -c ends its option list; a "--" would reach sys.argv.
		{"python", []string{"-x", "a b"}, "python|-c|print(1)|-x|a b"},
		{"javascript", nil, "qjs|-e|print(1)"},
		{"javascript", []string{"-x"}, "qjs|-e|print(1)|--|-x"},
		{"ruby", []string{"a"}, "ruby|-e|print(1)|--|a"},
	}
	for _, tc := range cases {
		got := strings.Join(codeRunArgs(codeRunFamilies[tc.family], "print(1)", tc.argv), "|")
		if got != tc.want {
			t.Fatalf("%s %v = %q, want %q", tc.family, tc.argv, got, tc.want)
		}
	}
}

// countingResolver resolves every ref to path and counts the calls.
type countingResolver struct {
	path  string
	calls atomic.Int32
	err   error
}

func (r *countingResolver) Resolve(_ context.Context, ref string) (*wasmmod.ResolvedModule, error) {
	r.calls.Add(1)
	if r.err != nil {
		return nil, r.err
	}
	return &wasmmod.ResolvedModule{Ref: ref, Path: r.path}, nil
}

func TestStartCodeRunLanguages(t *testing.T) {
	d := New(Config{CodeRunModules: map[string]string{
		"python": "python", "py": "python", "php": "php", "ruby": " ",
	}}, nil)
	d.byID["sb"] = &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted, socketPath: "/tmp/x.sock", workDir: "/w"}
	fake := &fakeStreamingClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return fake })
	module := filepath.Join(t.TempDir(), "python.wasm")
	if err := os.WriteFile(module, []byte("\x00asm"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := &countingResolver{path: module}
	d.SetModuleResolver(res)
	ctx := context.Background()

	// php has no known eval flag and ruby has no module: neither is offered.
	for _, lang := range []string{"php", "ruby", "cobol", ""} {
		_, err := d.StartCodeRun(ctx, "sb", CodeRunSpec{Language: lang, Code: "x"})
		var langErr *CodeRunLanguageError
		if !errors.As(err, &langErr) {
			t.Fatalf("%q: err = %v, want CodeRunLanguageError", lang, err)
		}
		if strings.Join(langErr.Configured, ",") != "py,python" || !strings.Contains(err.Error(), "py, python") {
			t.Fatalf("%q: configured = %v, message %q", lang, langErr.Configured, err)
		}
	}

	// The request language is matched case-insensitively; the module is
	// resolved once and cached.
	for i := 0; i < 2; i++ {
		st, err := d.StartCodeRun(ctx, "sb", CodeRunSpec{Language: " Python ", Code: "print(1)", Argv: []string{"a"}, Env: map[string]string{"K": "v"}, Timeout: time.Second, MaxOutputBytes: 99})
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
	}
	if res.calls.Load() != 1 {
		t.Fatalf("resolver called %d times, want 1", res.calls.Load())
	}
	p := fake.starts[0]
	if p.ModulePath != module || strings.Join(p.Caps.Args, "|") != "python|-c|print(1)|a" || p.Caps.Env["K"] != "v" ||
		p.Caps.WallTimeoutNs != int64(time.Second) || p.MaxOutputBytes != 99 || p.Stdin {
		t.Fatalf("payload = %+v", p)
	}

	// A start that fails after the module file vanished drops the cached
	// path, so the next run resolves again.
	fake.startErr = errors.New("compile module: no such file")
	if err := os.Remove(module); err != nil {
		t.Fatal(err)
	}
	if _, err := d.StartCodeRun(ctx, "sb", CodeRunSpec{Language: "py", Code: "1"}); err == nil {
		t.Fatal("failed start succeeded")
	}
	if _, err := d.StartCodeRun(ctx, "sb", CodeRunSpec{Language: "python", Code: "1"}); err == nil {
		t.Fatal("failed start succeeded")
	}
	if res.calls.Load() != 2 {
		t.Fatalf("resolver calls = %d, want 2 (python cached, py resolved)", res.calls.Load())
	}
	// python's cached path was dropped by its failed start.
	if _, err := d.StartCodeRun(ctx, "sb", CodeRunSpec{Language: "python", Code: "1"}); err == nil {
		t.Fatal("failed start succeeded")
	}
	if res.calls.Load() != 3 {
		t.Fatalf("resolver calls = %d, want 3", res.calls.Load())
	}
}

func TestStartCodeRunResolveErrors(t *testing.T) {
	d := New(Config{CodeRunModules: map[string]string{"python": "python"}}, nil)
	if _, err := d.StartCodeRun(context.Background(), "sb", CodeRunSpec{Language: "python"}); err == nil || !strings.Contains(err.Error(), "resolver") {
		t.Fatalf("no resolver = %v", err)
	}
	d.SetModuleResolver(&countingResolver{err: errors.New("not staged")})
	if _, err := d.StartCodeRun(context.Background(), "sb", CodeRunSpec{Language: "python"}); err == nil || !strings.Contains(err.Error(), "not staged") {
		t.Fatalf("resolve error = %v", err)
	}
	empty := &CodeRunLanguageError{Language: "python"}
	if !strings.Contains(empty.Error(), "SB_WASM_CODERUN_MODULES") {
		t.Fatalf("unconfigured message = %q", empty.Error())
	}
}

func TestStartCodeRunEndToEnd(t *testing.T) {
	// The stdio guest stands in for an interpreter: given -c or -e it
	// prints the code and its arguments.
	d, id := streamDriver(t, Config{CodeRunModules: map[string]string{"python": "python", "js": "javascript"}}, models.CreateSandboxRequest{})
	st, err := d.StartCodeRun(context.Background(), id, CodeRunSpec{Language: "python", Code: "print('a b')", Argv: []string{"x y"}})
	if err != nil {
		t.Fatal(err)
	}
	if res := mustDrain(t, st); res.stdout != "eval:print('a b')|x y" || res.exit.ExitCode != 0 {
		t.Fatalf("python: %+v %+v", res, res.exit)
	}
	_ = st.Close()
	st, err = d.StartCodeRun(context.Background(), id, CodeRunSpec{Language: "js", Code: "1", Argv: []string{"-v"}})
	if err != nil {
		t.Fatal(err)
	}
	if res := mustDrain(t, st); res.stdout != "eval:1|--|-v" {
		t.Fatalf("js: %+v", res)
	}
	_ = st.Close()
}

// TestStartCodeRunRealPython runs real CPython for WASI when the integration
// fixture has been fetched (integration-tests/fixtures/wasm/fetch.sh).
func TestStartCodeRunRealPython(t *testing.T) {
	python, err := filepath.Abs(filepath.Join("..", "..", "..", "integration-tests", "fixtures", "wasm", "python-3.12.0.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(python); err != nil {
		t.Skip("python-3.12.0.wasm not fetched; run integration-tests/fixtures/wasm/fetch.sh")
	}
	d, id := streamDriver(t, Config{CodeRunModules: map[string]string{"python": "python"}}, models.CreateSandboxRequest{})
	d.SetModuleResolver(fakeResolver{path: python})
	code := "import sys, os\nprint('hi', sys.argv[1:])\nopen('/work/py.txt', 'w').write('ok')\nprint('err', file=sys.stderr)\nsys.exit(4)"
	st, err := d.StartCodeRun(context.Background(), id, CodeRunSpec{Language: "python", Code: code, Argv: []string{"a b", "-x"}, Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	res := mustDrain(t, st)
	_ = st.Close()
	if res.stdout != "hi ['a b', '-x']\n" || res.stderr != "err\n" || res.exit.ExitCode != 4 {
		t.Fatalf("python: stdout %q stderr %q exit %+v", res.stdout, res.stderr, res.exit)
	}
	inst, _ := d.instance(id)
	if b, err := os.ReadFile(filepath.Join(inst.workDir, "py.txt")); err != nil || string(b) != "ok" {
		t.Fatalf("/work file = %q %v", b, err)
	}
}
