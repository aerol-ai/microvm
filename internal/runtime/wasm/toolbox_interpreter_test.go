package wasm

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/pkg/models"
)

// realPythonDriver is a sandbox whose code interpreter runs the real
// python.wasm (CPython 3.12 for WASI). It skips where the fixture was not
// fetched (integration-tests/fixtures/wasm/fetch.sh), so plain go test
// stays offline.
func realPythonDriver(t *testing.T) (*Driver, string, string) {
	t.Helper()
	python, err := filepath.Abs(filepath.Join("..", "..", "..", "integration-tests", "fixtures", "wasm", "python-3.12.0.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(python); err != nil {
		t.Skip("python-3.12.0.wasm not fetched; run integration-tests/fixtures/wasm/fetch.sh")
	}
	d, id := streamDriver(t, Config{CodeRunModules: map[string]string{"python": "python"}}, models.CreateSandboxRequest{})
	d.SetModuleResolver(fakeResolver{path: python})
	t.Cleanup(func() {
		inst, err := d.instance(id)
		if err == nil {
			d.killStreams(inst)
		}
	})
	return d, id, toolboxServer(t, d, id)
}

type daytonaRun struct {
	frames []map[string]any
	code   int
}

// text joins the frames of one type.
func (r daytonaRun) text(typ string) string {
	var sb strings.Builder
	for _, f := range r.frames {
		if f["type"] == typ {
			s, _ := f["text"].(string)
			sb.WriteString(s)
		}
	}
	return sb.String()
}

func (r daytonaRun) frame(typ string) map[string]any {
	for _, f := range r.frames {
		if f["type"] == typ {
			return f
		}
	}
	return nil
}

// runDaytona runs one execute WebSocket to its close.
func runDaytona(t *testing.T, base string, first map[string]any) daytonaRun {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(base, "http")+"/process/interpreter/execute", http.Header{"Authorization": {"Bearer tok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
	if err := conn.WriteJSON(first); err != nil {
		t.Fatal(err)
	}
	var run daytonaRun
	for {
		var f map[string]any
		if err := conn.ReadJSON(&f); err != nil {
			var ce *websocket.CloseError
			if errorsAs(err, &ce) {
				run.code = ce.Code
				return run
			}
			t.Fatalf("read: %v (frames %v)", err, run.frames)
		}
		run.frames = append(run.frames, f)
	}
}

func errorsAs(err error, target **websocket.CloseError) bool {
	ce, ok := err.(*websocket.CloseError)
	if ok {
		*target = ce
	}
	return ok
}

func interpHTTP(t *testing.T, method, url, body string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf strings.Builder
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		buf.WriteString(sc.Text())
		buf.WriteString("\n")
	}
	return resp.StatusCode, []byte(buf.String())
}

func TestRealPythonInterpreterDaytona(t *testing.T) {
	d, id, base := realPythonDriver(t)

	// State survives between runs of the default context.
	if run := runDaytona(t, base, map[string]any{"code": "x = 5"}); run.code != websocket.CloseNormalClosure || run.text("control") != "completed" {
		t.Fatalf("x = 5: %+v", run)
	}
	run := runDaytona(t, base, map[string]any{"code": "print(x)\nimport os\nos.write(2, b'raw\\n')\nprint(os.getcwd())"})
	if got := run.text("stdout"); got != "5\n/work\n" {
		t.Fatalf("print(x) stdout = %q (%+v)", got, run)
	}
	// os.write(2) bypasses sys.stderr: it reaches the run as the
	// instance's raw stderr.
	if got := run.text("stderr"); got != "raw\n" {
		t.Fatalf("raw stderr = %q", got)
	}
	run = runDaytona(t, base, map[string]any{"code": "print(y)"})
	if f := run.frame("error"); f == nil || f["name"] != "NameError" || !strings.Contains(f["traceback"].(string), "<stdin>") {
		t.Fatalf("NameError: %+v", run)
	}

	// Confinement: the guest sees only /work. A host file outside it, by
	// absolute path or by climbing out of /work, cannot be read.
	canary := filepath.Join(t.TempDir(), "canary.txt")
	if err := os.WriteFile(canary, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	inst, _ := d.instance(id)
	rel, err := filepath.Rel(inst.workDir, canary)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{canary, "/work/" + rel} {
		run = runDaytona(t, base, map[string]any{"code": "print(open(" + quotePy(path) + ").read())"})
		if strings.Contains(run.text("stdout"), "host secret") || run.frame("error") == nil {
			t.Fatalf("read %s: %+v", path, run)
		}
	}
	// Nothing of the interpreter's is left in the guest's /work.
	if entries, _ := os.ReadDir(inst.workDir); len(entries) != 0 {
		t.Fatalf("/work holds %d entries", len(entries))
	}
}

func TestRealPythonInterpreterTimeoutRestartsEmpty(t *testing.T) {
	_, _, base := realPythonDriver(t)
	status, body := interpHTTP(t, http.MethodPost, base+"/process/interpreter/context", `{}`)
	var info struct {
		ID     string `json:"id"`
		Cwd    string `json:"cwd"`
		Active bool   `json:"active"`
	}
	if err := json.Unmarshal(body, &info); status != http.StatusOK || err != nil || info.Cwd != "/work" || !info.Active {
		t.Fatalf("create = %d %s", status, body)
	}
	if run := runDaytona(t, base, map[string]any{"code": "x = 1", "contextId": info.ID}); run.text("control") != "completed" {
		t.Fatalf("x = 1: %+v", run)
	}
	// WASM has no signals: the timeout kills the instance.
	run := runDaytona(t, base, map[string]any{"code": "while True: pass", "contextId": info.ID, "timeout": 1})
	if run.code != 4008 || run.text("control") != "interrupted" {
		t.Fatalf("timeout: %+v", run)
	}
	_, body = interpHTTP(t, http.MethodGet, base+"/process/interpreter/context/"+info.ID, "")
	if !strings.Contains(string(body), `"active":false`) {
		t.Fatalf("after timeout = %s", body)
	}
	// The next run starts a new, empty interpreter.
	run = runDaytona(t, base, map[string]any{"code": "print('x' in dir())", "contextId": info.ID})
	if run.text("stdout") != "False\n" || run.text("control") != "completed" {
		t.Fatalf("after restart: %+v", run)
	}
	_, body = interpHTTP(t, http.MethodGet, base+"/process/interpreter/context/"+info.ID, "")
	if !strings.Contains(string(body), `"active":true`) {
		t.Fatalf("after the new run = %s", body)
	}

	// The AerolVM SDKs' interrupt: the run ends "interrupted" as on any
	// runtime, but the interpreter was killed, so the state is gone too.
	if run := runDaytona(t, base, map[string]any{"code": "y = 2", "contextId": info.ID}); run.text("control") != "completed" {
		t.Fatalf("y = 2: %+v", run)
	}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(base, "http")+"/process/interpreter/execute", http.Header{"Authorization": {"Bearer tok"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Minute))
	if err := conn.WriteJSON(map[string]any{"code": "print('spin', flush=True)\nwhile True: pass", "contextId": info.ID, "richOutput": true}); err != nil {
		t.Fatal(err)
	}
	var control string
	for {
		var f map[string]any
		err := conn.ReadJSON(&f)
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				t.Fatalf("interrupted run: %v", err)
			}
			break
		}
		if text, _ := f["text"].(string); f["type"] == "stdout" && strings.HasPrefix(text, "spin") {
			if err := conn.WriteJSON(map[string]string{"type": "interrupt"}); err != nil {
				t.Fatal(err)
			}
		}
		if f["type"] == "control" {
			control, _ = f["text"].(string)
		}
	}
	if control != "interrupted" {
		t.Fatalf("control = %q", control)
	}
	if run := runDaytona(t, base, map[string]any{"code": "print('y' in dir())", "contextId": info.ID}); run.text("stdout") != "False\n" {
		t.Fatalf("after the interrupt: %+v", run)
	}
}

func TestRealPythonInterpreterE2B(t *testing.T) {
	_, _, base := realPythonDriver(t)
	code := "class H:\n    def _repr_html_(self):\n        return '<b>hi</b>'\ndisplay(H())\nprint('out')\n6 * 7"
	body, _ := json.Marshal(map[string]any{"code": code, "context_id": nil, "language": nil, "env_vars": map[string]string{"V": "1"}})
	status, out := interpHTTP(t, http.MethodPost, base+"/interpreter/e2b/execute", string(body))
	if status != http.StatusOK {
		t.Fatalf("execute = %d %s", status, out)
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var v map[string]any
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		// E2B sends a keepalive every 5 s of quiet: the first interpreter's
		// start can take that long on a busy machine.
		if v["type"] != "keepalive" {
			lines = append(lines, v)
		}
	}
	var display, main map[string]any
	var stdout strings.Builder
	for _, l := range lines {
		switch {
		case l["type"] == "result" && l["is_main_result"] == false:
			display = l
		case l["type"] == "result":
			main = l
		case l["type"] == "stdout":
			// One line per write: print sends the text and the newline apart.
			stdout.WriteString(l["text"].(string))
		}
	}
	if display == nil || display["html"] != "<b>hi</b>" || main == nil || main["text"] != "42" || stdout.String() != "out\n" {
		t.Fatalf("lines = %v", lines)
	}
	if lines[0]["type"] != "number_of_executions" || lines[len(lines)-1]["type"] != "end_of_execution" {
		t.Fatalf("framing = %v", lines)
	}
	// E2B's contexts start in /work on WASM; python is the only language.
	status, out = interpHTTP(t, http.MethodPost, base+"/interpreter/e2b/contexts", `{}`)
	if status != http.StatusOK || !strings.Contains(string(out), `"cwd":"/work"`) {
		t.Fatalf("create = %d %s", status, out)
	}
	if status, out = interpHTTP(t, http.MethodPost, base+"/interpreter/e2b/contexts", `{"language":"javascript"}`); status != http.StatusBadRequest {
		t.Fatalf("javascript = %d %s", status, out)
	}
}
