package wasm

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func postCodeRun(t *testing.T, base, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/process/code-run", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestToolboxCodeRunEndToEnd(t *testing.T) {
	d, id := streamDriver(t, Config{CodeRunModules: map[string]string{"python": "python"}}, models.CreateSandboxRequest{})
	base := toolboxServer(t, d, id)
	status, out := postCodeRun(t, base, `{"language":"python","code":"print(1 + 2)","argv":["a b"]}`)
	if status != http.StatusOK || out["exitCode"] != float64(0) || out["result"] != "eval:print(1 + 2)|a b" {
		t.Fatalf("code-run = %d %v", status, out)
	}
	status, out = postCodeRun(t, base, `{"language":"ruby","code":"puts 1"}`)
	if status != http.StatusBadRequest || !strings.Contains(out["error"].(string), "supported: python") {
		t.Fatalf("unknown language = %d %v", status, out)
	}
}

func TestToolboxRealPythonCodeRunIsConfined(t *testing.T) {
	python, err := filepath.Abs(filepath.Join("..", "..", "..", "integration-tests", "fixtures", "wasm", "python-3.12.0.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(python); err != nil {
		t.Skip("python-3.12.0.wasm not fetched; run integration-tests/fixtures/wasm/fetch.sh")
	}
	d, id := streamDriver(t, Config{CodeRunModules: map[string]string{"python": "python"}}, models.CreateSandboxRequest{})
	d.SetModuleResolver(fakeResolver{path: python})
	base := toolboxServer(t, d, id)
	canary := filepath.Join(t.TempDir(), "canary.txt")
	if err := os.WriteFile(canary, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"language": "python",
		"code":     "import os\ntry:\n    print(open(" + quotePy(canary) + ").read())\nexcept OSError as e:\n    print('blocked', type(e).__name__)\nprint(sorted(os.listdir('/work')))",
	})
	status, out := postCodeRun(t, base, string(body))
	if status != http.StatusOK || strings.Contains(out["result"].(string), "host secret") || !strings.Contains(out["result"].(string), "blocked") {
		t.Fatalf("python code-run = %d %v", status, out)
	}
}

func quotePy(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
