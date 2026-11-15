package drivers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

func TestRegistry(t *testing.T) {
	d, ok := Lookup(codeinterp.LangPython)
	if !ok {
		t.Fatal("no python driver")
	}
	if d.FileName != "python_driver.py" || !bytes.Contains(d.Script, []byte("def main()")) ||
		!reflect.DeepEqual(d.Programs, []string{"python3", "python"}) {
		t.Fatalf("python driver = %+v", d)
	}
	if got := d.Args("/usr/bin/python3", "/d/x.py"); !reflect.DeepEqual(got, []string{"/usr/bin/python3", "/d/x.py"}) {
		t.Fatalf("Args = %q", got)
	}
	if _, ok := Lookup("cobol"); ok {
		t.Fatal("found a driver for cobol")
	}
	if got := Languages(); len(got) == 0 || got[0] != codeinterp.LangPython {
		t.Fatalf("Languages = %v", got)
	}

	// A language outside codeinterp.AllLanguages sorts after the known ones.
	registry["zz"] = d
	registry["aa"] = d
	defer func() {
		delete(registry, "zz")
		delete(registry, "aa")
	}()
	got := Languages()
	if got[0] != codeinterp.LangPython || !reflect.DeepEqual(got[len(got)-2:], []string{"aa", "zz"}) {
		t.Fatalf("Languages with extras = %v", got)
	}
}

// checkDriver checks lang's registration: programs, file name, argv, and
// that the script is the embedded one.
func checkDriver(t *testing.T, lang string, programs []string, fileName string, wantArgs []string, marker string) {
	t.Helper()
	d, ok := Lookup(lang)
	if !ok {
		t.Fatalf("no %s driver", lang)
	}
	if d.Language != lang || !reflect.DeepEqual(d.Programs, programs) || d.FileName != fileName ||
		!bytes.Contains(d.Script, []byte(marker)) {
		t.Fatalf("%s driver = %+v", lang, d)
	}
	if got := d.Args("/bin/prog", "/d/"+fileName); !reflect.DeepEqual(got, wantArgs) {
		t.Fatalf("%s Args = %q, want %q", lang, got, wantArgs)
	}
}

// checkDriverRefuses runs lang's script the wrong ways, outside fd mode
// and in fd mode without descriptors 3 and 4: it must exit non-zero and
// say why on stderr, not hang or start serving. Skipped without the
// interpreter.
func checkDriverRefuses(t *testing.T, lang string) {
	t.Helper()
	d, _ := Lookup(lang)
	program := ""
	for _, p := range d.Programs {
		if path, err := exec.LookPath(p); err == nil {
			program = path
			break
		}
	}
	if program == "" {
		t.Skipf("no %s interpreter", lang)
	}
	script := filepath.Join(t.TempDir(), d.FileName)
	if err := os.WriteFile(script, d.Script, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"stdio", "fd"} {
		ctx, cancel := context.WithTimeout(context.Background(), codeinterp.LaunchTimeout)
		args := d.Args(program, script)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Env = append(os.Environ(), "AEROL_INTERP_MODE="+mode, "AEROL_INTERP_NONCE=n")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		timedOut := ctx.Err() != nil
		cancel()
		if err == nil || timedOut || !strings.Contains(stderr.String(), "aerolvm interpreter driver: ") {
			t.Fatalf("%s driver in %s mode without descriptors: err %v, stderr %q", lang, mode, err, stderr.String())
		}
	}
}

func TestRegisterRejectsBadDrivers(t *testing.T) {
	py, _ := Lookup(codeinterp.LangPython)
	for name, d := range map[string]Driver{
		"duplicate":  py,
		"incomplete": {Language: "x"},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("register did not panic")
				}
			}()
			register(d)
		})
	}
}

// stdioDriver talks to a driver in stdio mode.
type stdioDriver struct {
	t  *testing.T
	w  io.Writer
	fr *codeinterp.FrameReader
}

type frame struct{ kind, payload string }

func (d *stdioDriver) send(kind, payload string) {
	d.t.Helper()
	if err := codeinterp.WriteFrame(d.w, kind, []byte(payload)); err != nil {
		d.t.Fatalf("write %s: %v", kind, err)
	}
}

func (d *stdioDriver) next() frame {
	d.t.Helper()
	kind, payload, err := d.fr.Read()
	if err != nil {
		d.t.Fatalf("read frame: %v", err)
	}
	return frame{kind, string(payload)}
}

// run sends code and returns the frames up to and including DONE.
func (d *stdioDriver) run(code string, env ...string) []frame {
	d.t.Helper()
	for _, kv := range env {
		d.send("ENV", kv)
	}
	d.send("EXEC", code)
	var out []frame
	for {
		f := d.next()
		out = append(out, f)
		if f.kind == "DONE" {
			return out
		}
	}
}

func joined(frames []frame, kind string) string {
	var sb strings.Builder
	for _, f := range frames {
		if f.kind == kind {
			sb.WriteString(f.payload)
		}
	}
	return sb.String()
}

func kinds(frames []frame) []string {
	var out []string
	for _, f := range frames {
		out = append(out, f.kind)
	}
	return out
}

// checkStdioProtocol is what the WASM runtime relies on: frames on stdin
// and stdout, output as OUT/ERR frames, no markers, no SYNC.
func checkStdioProtocol(t *testing.T, d *stdioDriver, full bool) {
	if f := d.next(); f.kind != "READY" || f.payload != "1" {
		t.Fatalf("first frame = %+v, want READY 1", f)
	}
	if got := kinds(d.run("x = 5")); !reflect.DeepEqual(got, []string{"COUNT", "DONE"}) {
		t.Fatalf("x = 5 frames = %v", got)
	}
	frames := d.run("print(x)\nimport sys\nsys.stderr.write('e')\nx + 1")
	if joined(frames, "OUT") != "5\n" || joined(frames, "ERR") != "e" {
		t.Fatalf("print frames = %+v", frames)
	}
	for _, f := range frames {
		if f.kind == "SYNC" || strings.Contains(f.payload, "\x1e") {
			t.Fatalf("stdio mode sent a marker: %+v", f)
		}
	}
	// print() writes its text and its newline separately; a line must still
	// reach the client as one chunk, and a partial line is flushed by the end
	// of the run.
	if f := d.run("print(x)"); !reflect.DeepEqual(kinds(f), []string{"COUNT", "OUT", "DONE"}) || f[1].payload != "5\n" {
		t.Fatalf("print(x) frames = %+v, want one OUT frame", f)
	}
	if f := d.run("import sys\nsys.stdout.write('a')\nsys.stdout.write('b')"); joined(f, "OUT") != "ab" {
		t.Fatalf("partial line frames = %+v", f)
	}
	var result struct {
		Data map[string]any `json:"data"`
		Main bool           `json:"main"`
	}
	if err := json.Unmarshal([]byte(joined(frames, "RESULT")), &result); err != nil || result.Data["text/plain"] != "6" || !result.Main {
		t.Fatalf("result = %+v (%v)", result, err)
	}
	if f := d.run("1/0"); kinds(f)[1] != "ERROR" || !strings.HasPrefix(f[1].payload, "ZeroDivisionError\x1fdivision by zero\x1fTraceback") || f[2].payload != "error" {
		t.Fatalf("1/0 frames = %+v", f)
	}
	// The real stdin is the request stream: user code must never read it.
	if f := d.run("input()"); !strings.HasPrefix(joined(f, "ERROR"), "EOFError") {
		t.Fatalf("input() frames = %+v", f)
	}
	// Even through sys.__stdout__, output stays framed.
	if f := d.run("import sys\nsys.stdout = sys.__stdout__\nprint('framed')\nsys.stdout.buffer.write(b'raw')"); joined(f, "OUT") != "framed\nraw" {
		t.Fatalf("__stdout__ frames = %+v", f)
	}
	if f := d.run("import os\nos.environ['V']", "V=1"); !strings.Contains(joined(f, "RESULT"), `"'1'"`) {
		t.Fatalf("env frames = %+v", f)
	}
	if f := d.run("import os\n'V' in os.environ"); !strings.Contains(joined(f, "RESULT"), `"False"`) {
		t.Fatalf("env leaked: %+v", f)
	}
	if f := d.run("!echo hi"); !strings.Contains(joined(f, "ERROR"), "not available") {
		t.Fatalf("!cmd frames = %+v", f)
	}
	if f := d.run("raise SystemExit(2)"); f[len(f)-1].payload != "ok" {
		t.Fatalf("SystemExit = %+v", f)
	}
	if f := d.run("raise KeyboardInterrupt"); f[len(f)-1].payload != "interrupted" || joined(f, "ERROR") != "" {
		t.Fatalf("KeyboardInterrupt = %+v", f)
	}
	if full {
		// A large write is split so no frame nears the host's cap.
		f := d.run("print('y' * (3 << 20))")
		if out := joined(f, "OUT"); len(out) != 3<<20+1 {
			t.Fatalf("large output = %d bytes", len(out))
		}
		if f := d.run("import asyncio\nawait asyncio.sleep(0)\n7"); !strings.Contains(joined(f, "RESULT"), `"7"`) {
			t.Fatalf("top-level await = %+v", f)
		}
	}
	d.send("QUIT", "")
}

func TestPythonDriverStdioMode(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "python_driver.py")
	if err := os.WriteFile(script, pythonDriver, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, script)
	cmd.Env = append(os.Environ(), "AEROL_INTERP_MODE=stdio")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	checkStdioProtocol(t, &stdioDriver{t: t, w: stdin, fr: codeinterp.NewFrameReader(stdout)}, true)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("driver exit after QUIT: %v (%s)", err, stderr.String())
	}
}

// TestPythonDriverStdioCwd covers how a WASM kernel gets its cwd: started
// with -c (no script file), it enters AEROL_INTERP_CWD before READY, and a
// cwd that does not exist is a FATAL start.
func TestPythonDriverStdioCwd(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, cwd, code string
		want            []string
	}{
		{name: "enters the cwd", cwd: cwd, code: "import os, sys\nprint(os.getcwd(), sys.path.count(''))",
			want: []string{"READY", "OUT:" + cwd + " 1\n"}},
		{name: "a missing cwd is fatal", cwd: filepath.Join(cwd, "missing"),
			want: []string{"FATAL:FileNotFoundError"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(python, "-c", `import sys;exec(compile(sys.argv.pop(1),"<driver>","exec"))`, string(pythonDriver))
			cmd.Env = append(os.Environ(), "AEROL_INTERP_MODE=stdio", "AEROL_INTERP_CWD="+tc.cwd)
			var in bytes.Buffer
			if tc.code != "" {
				_ = codeinterp.WriteFrame(&in, "EXEC", []byte(tc.code))
			}
			cmd.Stdin = &in
			out, _ := cmd.Output()
			fr := codeinterp.NewFrameReader(bytes.NewReader(out))
			var got []string
			for {
				kind, payload, err := fr.Read()
				if err != nil {
					break
				}
				switch kind {
				case "READY":
					got = append(got, kind)
				case "OUT":
					got = append(got, kind+":"+string(payload))
				case "FATAL":
					name, _, _ := strings.Cut(string(payload), ":")
					got = append(got, kind+":"+name)
				}
			}
			// OUT arrives as one frame per write: join them.
			if len(got) > 2 && strings.HasPrefix(got[1], "OUT:") {
				joinedOut := "OUT:"
				for _, g := range got[1:] {
					joinedOut += strings.TrimPrefix(g, "OUT:")
				}
				got = []string{got[0], joinedOut}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("frames = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPythonDriverEOFExits(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	script := filepath.Join(t.TempDir(), "python_driver.py")
	if err := os.WriteFile(script, pythonDriver, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, script)
	cmd.Env = append(os.Environ(), "AEROL_INTERP_MODE=stdio")
	cmd.Stdin = strings.NewReader("EXEC 4\nx=1\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("driver exit at EOF: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("READY 1\n1COUNT 1\n1DONE 2\nok")) {
		t.Fatalf("output = %q", out)
	}

	// A driver that cannot set up says FATAL and exits non-zero.
	cmd = exec.Command(python, script)
	cmd.Env = append(os.Environ(), "AEROL_INTERP_MODE=fd") // no fd 3 or 4
	if err := cmd.Run(); err == nil {
		t.Fatal("fd mode without descriptors succeeded")
	}
}

// TestPythonDriverUnderWASI runs the driver inside CPython for WASI, the
// way the WASM runtime will. Point AEROL_TEST_PYTHON_WASM at a
// python-3.12 .wasm (integration-tests/fixtures/wasm/fetch.sh downloads
// one); without it the test is skipped, so plain go test stays offline.
func TestPythonDriverUnderWASI(t *testing.T) {
	wasmPath := os.Getenv("AEROL_TEST_PYTHON_WASM")
	if wasmPath == "" {
		t.Skip("AEROL_TEST_PYTHON_WASM not set")
	}
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "python_driver.py"), pythonDriver, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)
	compiled, err := r.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	var stderr bytes.Buffer
	cfg := wazero.NewModuleConfig().
		WithArgs("python", "/driver/python_driver.py").
		WithEnv("AEROL_INTERP_MODE", "stdio").
		WithStdin(stdinR).WithStdout(stdoutW).WithStderr(&stderr).
		WithFSConfig(wazero.NewFSConfig().WithDirMount(dir, "/driver")).
		WithSysWalltime().WithSysNanotime().WithRandSource(rand.Reader)
	done := make(chan error, 1)
	go func() {
		_, err := r.InstantiateModule(ctx, compiled, cfg)
		_ = stdoutW.Close()
		done <- err
	}()
	checkStdioProtocol(t, &stdioDriver{t: t, w: stdinW, fr: codeinterp.NewFrameReader(stdoutR)}, false)
	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "exit_code(0)") {
			t.Fatalf("python.wasm: %v (%s)", err, stderr.String())
		}
	case <-ctx.Done():
		t.Fatalf("python.wasm did not exit after QUIT: %s", stderr.String())
	}
}
