package proc

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/drivers"
)

// pythonEnv is the environment the real-python tests run with. Set
// AEROL_TEST_PYTHON_DIR to a folder holding a python3 with IPython, pandas
// and matplotlib to run the tests that need them.
func pythonEnv(t *testing.T) []string {
	t.Helper()
	env := os.Environ()
	if dir := os.Getenv("AEROL_TEST_PYTHON_DIR"); dir != "" {
		env = append(env, "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	if _, err := findProgram(pythonDriver(), envValue(env, "PATH")); err != nil {
		t.Skipf("no python interpreter: %v", err)
	}
	return env
}

func pythonDriver() drivers.Driver {
	d, _ := drivers.Lookup(codeinterp.LangPython)
	return d
}

// pythonHas reports whether the test python can import module.
func pythonHas(t *testing.T, env []string, module string) bool {
	t.Helper()
	program, err := findProgram(pythonDriver(), envValue(env, "PATH"))
	if err != nil {
		return false
	}
	cmd := exec.Command(program, "-c", "import "+module)
	cmd.Env = env
	return cmd.Run() == nil
}

// launchPython starts a real python kernel. ipython picks the driver's
// runner: "0" forces the plain one.
func launchPython(t *testing.T, ipython string) (*kernel, string) {
	t.Helper()
	env := pythonEnv(t)
	cwd := t.TempDir()
	l := New(Config{Env: func() []string { return env }, DriverDir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), codeinterp.LaunchTimeout)
	defer cancel()
	k, err := l.Launch(ctx, codeinterp.Spec{
		Language: codeinterp.LangPython,
		Cwd:      cwd,
		Env:      map[string]string{"AEROL_INTERP_IPYTHON": ipython},
	})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return k.(*kernel), cwd
}

func mustRun(t *testing.T, k codeinterp.Kernel, code string, wantStatus string) *events {
	t.Helper()
	out, ev := execute(t, k, code, nil)
	if out.Status != wantStatus || out.Died {
		t.Fatalf("run %q = %+v, want %s; events %q", code, out, wantStatus, ev.trace())
	}
	return ev
}

func TestPythonPlainDriver(t *testing.T) {
	k, cwd := launchPython(t, "0")

	mustRun(t, k, "x = 5", "ok")
	if got := mustRun(t, k, "print(x)", "ok").stream(codeinterp.EventStdout); got != "5\n" {
		t.Fatalf("print(x) = %q", got)
	}

	ev := mustRun(t, k, "print('a')\ndisplay(1)\nprint('b')\nx * 2", "ok")
	want := []string{"count:3", "out:a\n", "result:1:false", "out:b\n", "result:10:true"}
	if got := merged(ev); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %q, want %q", got, want)
	}

	ev = mustRun(t, k, "def f():\n    raise ValueError('boom')\nf()", "error")
	var errEvent codeinterp.Event
	for _, e := range ev.list() {
		if e.Kind == codeinterp.EventError {
			errEvent = e
		}
	}
	if errEvent.ErrName != "ValueError" || errEvent.ErrValue != "boom" ||
		!strings.Contains(errEvent.ErrTraceback, `File "<stdin>", line 2, in f`) ||
		strings.Contains(errEvent.ErrTraceback, "python_driver") {
		t.Fatalf("error event = %+v", errEvent)
	}

	// Syntax errors carry no driver frames either.
	ev = mustRun(t, k, "x = (", "error")
	if tb := ev.list()[1].ErrTraceback; ev.list()[1].ErrName != "SyntaxError" || strings.Contains(tb, "ast.py") {
		t.Fatalf("syntax error = %+v", ev.list()[1])
	}

	if got := mustRun(t, k, "import os\nos.getcwd()", "ok").trace(); !strings.Contains(strings.Join(got, " "), filepath.Base(cwd)) {
		t.Fatalf("cwd result = %q, want %s", got, cwd)
	}
	mustRun(t, k, "raise SystemExit(3)", "ok")
	mustRun(t, k, "raise KeyboardInterrupt", "interrupted")
	if got := mustRun(t, k, "1;", "ok").trace(); len(got) != 1 {
		t.Fatalf("a trailing semicolon still showed the value: %q", got)
	}
	if got := mustRun(t, k, "None", "ok").trace(); len(got) != 1 {
		t.Fatalf("None was shown: %q", got)
	}
	ev = mustRun(t, k, "input()", "error")
	if got := ev.trace(); got[len(got)-1] != "error:EOFError:EOF when reading a line" {
		t.Fatalf("input() = %q", got)
	}
	// The state survived all of that.
	if got := mustRun(t, k, "x", "ok").trace(); got[1] != "result:5:true" {
		t.Fatalf("x = %q", got)
	}
}

func TestPythonRichResults(t *testing.T) {
	k, _ := launchPython(t, "0")
	code := `
class Rich:
    def _repr_html_(self): return "<b>hi</b>"
    def _repr_png_(self): return b"\x89PNG"
    def _repr_json_(self): return {"a": [1, 2.5, float("nan")]}
    def _repr_markdown_(self): return ("# md", {"meta": 1})
    def _repr_latex_(self): raise RuntimeError("broken formatter")
Rich()`
	ev := mustRun(t, k, code, "ok")
	var bundle map[string]any
	for _, e := range ev.list() {
		if e.Kind == codeinterp.EventResult {
			bundle = e.Bundle
		}
	}
	if bundle["text/html"] != "<b>hi</b>" || bundle["text/markdown"] != "# md" ||
		bundle["image/png"] != base64.StdEncoding.EncodeToString([]byte("\x89PNG")) {
		t.Fatalf("bundle = %v", bundle)
	}
	if fmt.Sprint(bundle["application/json"]) != "map[a:[1 2.5 <nil>]]" {
		t.Fatalf("json = %v", bundle["application/json"])
	}
	if !strings.Contains(ev.stream(codeinterp.EventStderr), "broken formatter") {
		t.Fatalf("a broken formatter was silent: %q", ev.stream(codeinterp.EventStderr))
	}

	// A class is shown by its repr only.
	if got := mustRun(t, k, "Rich", "ok").list()[1].Bundle; len(got) != 1 {
		t.Fatalf("class bundle = %v", got)
	}
	// A broken __repr__ is the run's error, from the user's frame.
	ev = mustRun(t, k, "class B:\n    def __repr__(self): raise ValueError('r')\nB()", "error")
	if tb := ev.list()[1].ErrTraceback; !strings.HasPrefix(tb, "Traceback") || !strings.Contains(tb, `File "<stdin>", line 2, in __repr__`) {
		t.Fatalf("repr traceback = %q", tb)
	}
}

func TestPythonSubprocessOutputAndShell(t *testing.T) {
	k, _ := launchPython(t, "0")
	ev := mustRun(t, k, "import os\nprint('py', flush=True)\nos.system('echo sub; echo suberr >&2')\nprint('after')", "ok")
	if got := ev.stream(codeinterp.EventStdout); got != "py\nsub\nafter\n" {
		t.Fatalf("stdout = %q", got)
	}
	if got := ev.stream(codeinterp.EventStderr); got != "suberr\n" {
		t.Fatalf("stderr = %q", got)
	}
	ev = mustRun(t, k, "for i in range(2):\n    !echo bang $((1+1))\n_exit_code", "ok")
	if got := ev.stream(codeinterp.EventStdout); got != "bang 2\nbang 2\n" {
		t.Fatalf("!cmd stdout = %q", got)
	}
	// A background job that keeps stdout open does not hold the run.
	mustRun(t, k, "import subprocess\nsubprocess.Popen('sleep 3', shell=True)", "ok")
	if got := mustRun(t, k, "print('next')", "ok").stream(codeinterp.EventStdout); got != "next\n" {
		t.Fatalf("next run stdout = %q", got)
	}
}

func TestPythonLargeOutputInOrder(t *testing.T) {
	k, _ := launchPython(t, "0")
	ev := mustRun(t, k, "print(''.join('%07d\\n' % i for i in range(300 * 1024 // 8)), end='')\n'tail'", "ok")
	got := ev.stream(codeinterp.EventStdout)
	if len(got) != 300*1024 {
		t.Fatalf("stdout length = %d", len(got))
	}
	for i, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if line != fmt.Sprintf("%07d", i) {
			t.Fatalf("line %d = %q", i, line)
		}
	}
	trace := ev.trace()
	if trace[len(trace)-1] != "result:'tail':true" {
		t.Fatalf("result not last: %q", trace[len(trace)-1])
	}
}

func TestPythonInterruptAndEnv(t *testing.T) {
	k, _ := launchPython(t, "0")
	mustRun(t, k, "x = 1", "ok")
	// SIGINT to an idle kernel must not end it.
	if err := k.Interrupt(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	mustRun(t, k, "x", "ok")

	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = k.Interrupt()
	}()
	out, ev := execute(t, k, "import time\nprint('start', flush=True)\ntime.sleep(20)", nil)
	if !out.Interrupted() || out.Died {
		t.Fatalf("outcome = %+v (%q)", out, ev.trace())
	}
	for _, e := range ev.list() {
		if e.Kind == codeinterp.EventError {
			t.Fatalf("an interrupt is not an error: %+v", e)
		}
	}

	out, ev = execute(t, k, "import os\nos.environ.get('RUN_VAR')", map[string]string{"RUN_VAR": "v"})
	if out.Status != "ok" || ev.trace()[1] != "result:'v':true" {
		t.Fatalf("env run = %+v %q", out, ev.trace())
	}
	if got := mustRun(t, k, "os.environ.get('RUN_VAR')", "ok").trace(); len(got) != 1 {
		t.Fatalf("env leaked into the next run: %q", got)
	}
	if got := mustRun(t, k, "os.environ.get('AEROL_INTERP_NONCE')", "ok").trace(); len(got) != 1 {
		t.Fatalf("the marker nonce is visible to user code: %q", got)
	}
}

func TestPythonCloseKillsChildren(t *testing.T) {
	k, _ := launchPython(t, "0")
	ev := mustRun(t, k, "import subprocess\np = subprocess.Popen(['sleep', '60'])\nprint(p.pid)", "ok")
	pid, err := strconv.Atoi(strings.TrimSpace(ev.stream(codeinterp.EventStdout)))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, k.Done(), "driver exit")
	deadline := time.Now().Add(10 * time.Second)
	for {
		// The orphan is reaped by init; until then it is a zombie, which
		// signal 0 still finds, so check it can no longer run.
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH || isZombie(pid) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("child %d survived Close", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func isZombie(pid int) bool {
	// Linux: the state follows the parenthesised command name. Slim images
	// have no ps.
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		if i := strings.LastIndexByte(string(stat), ')'); i >= 0 && i+2 < len(stat) {
			return stat[i+2] == 'Z'
		}
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
}

func TestPythonFigureAndDataFrame(t *testing.T) {
	env := pythonEnv(t)
	if !pythonHas(t, env, "matplotlib") || !pythonHas(t, env, "pandas") {
		t.Skip("python has no matplotlib or pandas (set AEROL_TEST_PYTHON_DIR)")
	}
	for _, ipython := range []string{"0", "1"} {
		t.Run("ipython="+ipython, func(t *testing.T) {
			if ipython == "1" && !pythonHas(t, env, "IPython") {
				t.Skip("no IPython")
			}
			k, _ := launchPython(t, ipython)
			ev := mustRun(t, k, "import matplotlib.pyplot as plt\nplt.plot([1, 2])\nplt.show()", "ok")
			var fig map[string]any
			for _, e := range ev.list() {
				if e.Kind == codeinterp.EventResult && e.Bundle["image/png"] != nil {
					fig = e.Bundle
				}
			}
			png, _ := base64.StdEncoding.DecodeString(fmt.Sprint(fig["image/png"]))
			if !strings.HasPrefix(string(png), "\x89PNG") || !strings.HasPrefix(fmt.Sprint(fig["text/plain"]), "<Figure size") {
				t.Fatalf("figure result = %v", fig)
			}
			if strings.Contains(ev.stream(codeinterp.EventStderr), "non-interactive") {
				t.Fatalf("Agg warning reached the user: %q", ev.stream(codeinterp.EventStderr))
			}
			// Figures are closed after they are sent.
			if got := mustRun(t, k, "len(plt.get_fignums())", "ok").trace(); got[1] != "result:0:true" {
				t.Fatalf("open figures = %q", got)
			}

			ev = mustRun(t, k, "import pandas as pd\npd.DataFrame({'a': [1, None], 't': pd.to_datetime(['2024-01-02', '2024-01-03'])})", "ok")
			var df map[string]any
			for _, e := range ev.list() {
				if e.Kind == codeinterp.EventResult {
					df = e.Bundle
				}
			}
			data := fmt.Sprint(df["e2b/data"])
			if df["text/html"] == nil || !strings.Contains(data, "a:[1.0 <nil>]") || !strings.Contains(data, "2024-01-02T00:00:00") {
				t.Fatalf("dataframe result = %v", df)
			}
		})
	}
}

func TestPythonIPythonDriver(t *testing.T) {
	env := pythonEnv(t)
	if !pythonHas(t, env, "IPython") {
		t.Skip("python has no IPython (set AEROL_TEST_PYTHON_DIR)")
	}
	k, _ := launchPython(t, "1")
	mustRun(t, k, "x = 5", "ok")
	ev := mustRun(t, k, "print(x)\n!echo shell\n%time y = 1\nx * 2", "ok")
	out := ev.stream(codeinterp.EventStdout)
	if !strings.HasPrefix(out, "5\nshell\n") || !strings.Contains(out, "Wall time") {
		t.Fatalf("stdout = %q", out)
	}
	trace := ev.trace()
	if trace[0] != "count:2" || trace[len(trace)-1] != "result:10:true" {
		t.Fatalf("events = %q", trace)
	}
	ev = mustRun(t, k, "1/0", "error")
	e := ev.list()[len(ev.list())-1]
	if e.ErrName != "ZeroDivisionError" || !strings.Contains(e.ErrTraceback, "----> 1 1/0") || strings.Contains(e.ErrTraceback, "\x1b[") {
		t.Fatalf("error = %+v", e)
	}
	mustRun(t, k, "raise SystemExit", "ok")
	mustRun(t, k, "raise KeyboardInterrupt", "interrupted")
	ev = mustRun(t, k, "from IPython.display import display, HTML\ndisplay(HTML('<i>x</i>'))", "ok")
	if got := ev.list()[1].Bundle["text/html"]; got != "<i>x</i>" {
		t.Fatalf("display(HTML) = %v", ev.list()[1].Bundle)
	}
}

// TestPythonPrintIsOneChunkPerLine guards the driver's line buffering: with
// PYTHONUNBUFFERED, print() made two writes (text, then newline) and a client
// could see "5" and "\n" as two chunks.
func TestPythonPrintIsOneChunkPerLine(t *testing.T) {
	k, _ := launchPython(t, "0")
	for round := 0; round < 5; round++ {
		ev := mustRun(t, k, "for i in range(50):\n    print(i)", "ok")
		n := 0
		for _, e := range ev.list() {
			if e.Kind != codeinterp.EventStdout {
				continue
			}
			n++
			if !strings.HasSuffix(e.Text, "\n") {
				t.Fatalf("round %d: stdout chunk %q ends mid-line", round, e.Text)
			}
		}
		if n == 0 {
			t.Fatal("no stdout")
		}
	}
	if got := mustRun(t, k, "import sys\nsys.stdout.write('partial')", "ok").stream(codeinterp.EventStdout); got != "partial" {
		t.Fatalf("partial line = %q", got)
	}
}
