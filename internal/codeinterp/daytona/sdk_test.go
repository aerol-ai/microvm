package daytona

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	daytonasdk "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	daytonaoptions "github.com/daytonaio/daytona/libs/sdk-go/pkg/options"
	toolbox "github.com/daytonaio/daytona/libs/toolbox-api-client-go"
	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/proc"
)

// sdkClient is the Daytona Go SDK pinned in go.mod, pointed at the handler.
// Its toolbox client decodes contexts strictly (all five fields required),
// so these tests also prove the wire shapes.
func sdkClient(e *testEnv) *daytonasdk.CodeInterpreterService {
	cfg := toolbox.NewConfiguration()
	cfg.Servers = toolbox.ServerConfigurations{{URL: e.ts.URL}}
	cfg.HTTPClient = e.ts.Client()
	cfg.AddDefaultHeader("Authorization", "Bearer token")
	return daytonasdk.NewCodeInterpreterService(toolbox.NewAPIClient(cfg), nil)
}

func sdkCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func runSDK(t *testing.T, ci *daytonasdk.CodeInterpreterService, code string, opts ...func(*daytonaoptions.RunCode)) (stdout string, result *daytonaResult) {
	t.Helper()
	ch, err := ci.RunCode(sdkCtx(t), code, opts...)
	if err != nil {
		t.Fatalf("RunCode: %v", err)
	}
	var sb strings.Builder
	for msg := range ch.Stdout {
		sb.WriteString(msg.Text)
	}
	done := <-ch.Done
	r := &daytonaResult{stdout: done.Stdout, stderr: done.Stderr}
	if done.Error != nil {
		r.errName, r.errValue = done.Error.Name, done.Error.Value
	}
	return sb.String(), r
}

type daytonaResult struct {
	stdout, stderr, errName, errValue string
}

func TestDaytonaGoSDK(t *testing.T) {
	l := &fakeLauncher{}
	e := newTestEnv(t, l, nil)
	ci := sdkClient(e)
	ctx := sdkCtx(t)

	cwd := "/srv/app"
	created, err := ci.CreateContext(ctx, &cwd)
	if err != nil {
		t.Fatalf("CreateContext: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" || created["cwd"] != cwd || created["language"] != "python" || created["active"] != true || created["createdAt"] == "" {
		t.Fatalf("context = %v", created)
	}

	_, r := runSDK(t, ci, "print hi\nerr warn\nresult", daytonaoptions.WithCustomContext(id),
		daytonaoptions.WithEnv(map[string]string{"K": "v"}), daytonaoptions.WithInterpreterTimeout(5*time.Second))
	if r.stdout != "hi" || r.stderr != "warn" || r.errName != "" {
		t.Fatalf("run = %+v", r)
	}
	if _, r = runSDK(t, ci, "fail", daytonaoptions.WithCustomContext(id)); r.errName != "ValueError" || r.errValue != "bad" {
		t.Fatalf("error run = %+v", r)
	}
	// No context: the default one.
	if _, r = runSDK(t, ci, "print default"); r.stdout != "default" || r.errName != "" {
		t.Fatalf("default run = %+v", r)
	}

	list, err := ci.ListContexts(ctx)
	if err != nil || len(list) != 1 || list[0]["id"] != id {
		t.Fatalf("ListContexts = %v, %v", list, err)
	}
	if err := ci.DeleteContext(ctx, id); err != nil {
		t.Fatalf("DeleteContext: %v", err)
	}
	if err := ci.DeleteContext(ctx, id); err == nil {
		t.Fatal("deleting a deleted context succeeded")
	}
	if err := ci.DeleteContext(ctx, DefaultContextID); err == nil {
		t.Fatal("deleting the default context succeeded")
	}
	if list, err = ci.ListContexts(ctx); err != nil || len(list) != 0 {
		t.Fatalf("ListContexts after delete = %v, %v", list, err)
	}
}

// pythonEnv serves the handler with the real process launcher, so runs go
// through python_driver.py. Skipped without python3.
func pythonEnv(t *testing.T) *testEnv {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3")
	}
	l := proc.New(proc.Config{DriverDir: t.TempDir()})
	return newTestEnv(t, l, func(o *codeinterp.Options) { o.DefaultCwd = t.TempDir() })
}

func TestPythonEndToEnd(t *testing.T) {
	e := pythonEnv(t)

	if res := e.run(t, ExecuteRequest{Code: "x = 5"}); res.text("control") != "completed" || res.closeCode != websocket.CloseNormalClosure {
		t.Fatalf("x = 5: %v %d %q", res.frames, res.closeCode, res.closeReason)
	}
	if res := e.run(t, ExecuteRequest{Code: "print(x)"}); res.text("stdout") != "5\n" {
		t.Fatalf("print(x) = %v", res.frames)
	}

	res := e.run(t, ExecuteRequest{Code: "1/0"})
	if want := []string{"error", "control"}; strings.Join(res.types(), ",") != strings.Join(want, ",") {
		t.Fatalf("1/0 frames = %v", res.frames)
	}
	if f := res.frames[0]; f["name"] != "ZeroDivisionError" || f["value"] != "division by zero" ||
		!strings.Contains(f["traceback"].(string), `File "<stdin>", line 1`) || res.text("control") != "completed" {
		t.Fatalf("error frame = %v", f)
	}

	start := time.Now()
	res = e.run(t, map[string]any{"code": "import time\ntime.sleep(10)", "timeout": 1})
	if res.text("control") != "interrupted" || res.closeCode != CloseTimeout || time.Since(start) > 8*time.Second {
		t.Fatalf("timeout = %v %d after %s", res.frames, res.closeCode, time.Since(start))
	}
	// The interrupted context still has its state.
	if res = e.run(t, ExecuteRequest{Code: "print(x)"}); res.text("stdout") != "5\n" {
		t.Fatalf("state after interrupt = %v", res.frames)
	}

	if res = e.run(t, ExecuteRequest{Code: `import os; os.system("echo sub")`}); res.text("stdout") != "sub\n" {
		t.Fatalf("os.system = %v", res.frames)
	}

	const size = 300 * 1024
	res = e.run(t, ExecuteRequest{Code: fmt.Sprintf("print(''.join('%%07d\\n' %% i for i in range(%d)), end='')", size/8)})
	out := res.text("stdout")
	if len(out) != size {
		t.Fatalf("large print: %d bytes, want %d", len(out), size)
	}
	for i, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line != fmt.Sprintf("%07d", i) {
			t.Fatalf("line %d = %q", i, line)
		}
	}

	res = e.run(t, ExecuteRequest{Code: "print('a')\nx * 2", RichOutput: true})
	if strings.Join(res.types(), ",") != "execution_count,stdout,result,control" || res.frames[2]["text"] != "10" {
		t.Fatalf("rich run = %v", res.frames)
	}
}

// TestLanguagesEndToEnd sends non-python runs through the WebSocket's
// "language" field: each language gets its own default context, started
// by the real process launcher, and its output, results and errors reach
// the client as frames. A language whose interpreter is missing is skipped.
func TestLanguagesEndToEnd(t *testing.T) {
	type run struct {
		code, stdout, result string
		// fails: one error frame, named errName.
		fails   bool
		errName string
	}
	cases := []struct {
		lang, program string
		runs          []run
	}{
		{codeinterp.LangJavaScript, "node", []run{
			{code: "let x = 5"},
			{code: "console.log(x); x * 2", stdout: "5\n", result: "10"},
			{code: "null.f()", fails: true, errName: "TypeError"},
		}},
		{codeinterp.LangTypeScript, "node", []run{
			{code: "const message: string = 'Hello, World!'; console.log(message)", stdout: "Hello, World!\n"},
		}},
		{codeinterp.LangBash, "bash", []run{
			{code: "x=7; cd /"},
			{code: "echo $x; pwd", stdout: "7\n/\n"},
			{code: "false", fails: true},
		}},
		{codeinterp.LangR, "Rscript", []run{
			{code: "x <- 3"},
			{code: "cat(x, '\\n'); x + 1", stdout: "3 \n", result: "[1] 4"},
		}},
		{codeinterp.LangJava, "java", []run{
			{code: "int x = 9;"},
			{code: "System.out.println(x);\nx + 1", stdout: "9\n", result: "10"},
		}},
	}
	l := proc.New(proc.Config{DriverDir: t.TempDir()})
	e := newTestEnv(t, l, func(o *codeinterp.Options) {
		o.DefaultCwd = t.TempDir()
		o.Limit = codeinterp.NewLimit(len(cases) + 1)
	})
	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			if _, err := exec.LookPath(tc.program); err != nil {
				t.Skipf("no %s", tc.program)
			}
			for _, r := range tc.runs {
				res := e.run(t, ExecuteRequest{Code: r.code, Language: tc.lang, RichOutput: true})
				var result, errName string
				errs := 0
				for _, f := range res.frames {
					switch f["type"] {
					case "result":
						result, _ = f["text"].(string)
					case "error":
						errs++
						errName, _ = f["name"].(string)
					}
				}
				// Daytona ends a failed run as "completed" too.
				if res.text("control") != "completed" || res.closeCode != websocket.CloseNormalClosure ||
					res.text("stdout") != r.stdout || result != r.result || r.fails != (errs == 1) || errName != r.errName {
					t.Fatalf("%s run %q: frames %v close %d %q", tc.lang, r.code, res.frames, res.closeCode, res.closeReason)
				}
			}
		})
	}
	// Each language ran in its own default context; python's is untouched.
	if _, err := exec.LookPath("python3"); err != nil {
		return
	}
	if res := e.run(t, ExecuteRequest{Code: "print('x' in dir())"}); res.text("stdout") != "False\n" {
		t.Fatalf("python default context = %v", res.frames)
	}
}

func TestPythonEndToEndSDK(t *testing.T) {
	e := pythonEnv(t)
	ci := sdkClient(e)
	created, err := ci.CreateContext(sdkCtx(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	id := created["id"].(string)
	if _, r := runSDK(t, ci, "x = 41", daytonaoptions.WithCustomContext(id)); r.errName != "" {
		t.Fatalf("x = 41: %+v", r)
	}
	if out, r := runSDK(t, ci, "print(x + 1)", daytonaoptions.WithCustomContext(id)); out != "42\n" || r.stdout != "42\n" {
		t.Fatalf("print = %q %+v", out, r)
	}
	// Another context has its own variables.
	if _, r := runSDK(t, ci, "print(x)"); r.errName != "NameError" {
		t.Fatalf("default context saw x: %+v", r)
	}
}
