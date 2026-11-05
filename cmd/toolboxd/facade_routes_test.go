package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/api/daytona"
	"github.com/aerol-ai/microvm/pkg/api/e2b"
	"github.com/aerol-ai/microvm/pkg/api/runloop"
)

// daytonaPrefixCalls expands the prefixes the Daytona facade forwards whole
// into the concrete calls the Daytona SDK makes under them, taken from the
// toolbox client pinned in go.mod (toolbox-api-client-go v0.177.0:
// api_git.go, api_lsp.go, api_process.go, api_interpreter.go). Ids are
// samples.
var daytonaPrefixCalls = map[string][][2]string{
	"/git/": {
		{http.MethodPost, "/git/add"}, {http.MethodPost, "/git/checkout"}, {http.MethodPost, "/git/clone"},
		{http.MethodPost, "/git/commit"}, {http.MethodPost, "/git/branches"}, {http.MethodDelete, "/git/branches"},
		{http.MethodGet, "/git/history"}, {http.MethodGet, "/git/status"}, {http.MethodGet, "/git/branches"},
		{http.MethodPost, "/git/pull"}, {http.MethodPost, "/git/push"},
	},
	"/lsp/": {
		{http.MethodPost, "/lsp/completions"}, {http.MethodPost, "/lsp/did-close"}, {http.MethodPost, "/lsp/did-open"},
		{http.MethodGet, "/lsp/document-symbols"}, {http.MethodPost, "/lsp/start"}, {http.MethodPost, "/lsp/stop"},
		{http.MethodGet, "/lsp/workspacesymbols"},
	},
	"/process/session/": {
		{http.MethodGet, "/process/session/entrypoint"}, {http.MethodGet, "/process/session/entrypoint/logs"},
		{http.MethodGet, "/process/session/s1"}, {http.MethodDelete, "/process/session/s1"},
		{http.MethodPost, "/process/session/s1/exec"}, {http.MethodGet, "/process/session/s1/command/c1"},
		{http.MethodGet, "/process/session/s1/command/c1/logs"}, {http.MethodPost, "/process/session/s1/command/c1/input"},
	},
	"/process/session": {
		{http.MethodPost, "/process/session"}, {http.MethodGet, "/process/session"},
	},
	"/process/pty/": {
		{http.MethodGet, "/process/pty/s1"}, {http.MethodDelete, "/process/pty/s1"},
		{http.MethodPost, "/process/pty/s1/resize"}, {http.MethodGet, "/process/pty/s1/connect"},
	},
	"/process/pty": {
		{http.MethodPost, "/process/pty"}, {http.MethodGet, "/process/pty"},
	},
	"/process/interpreter/": {
		{http.MethodPost, "/process/interpreter/context"}, {http.MethodGet, "/process/interpreter/context"},
		{http.MethodDelete, "/process/interpreter/context/x1"}, {http.MethodGet, "/process/interpreter/execute"},
	},
}

type facadeProbe struct {
	facade, method, path string
}

func facadeProbes(t *testing.T) []facadeProbe {
	t.Helper()
	var probes []facadeProbe
	for _, call := range daytona.ToolboxCalls() {
		if subs, ok := daytonaPrefixCalls[call.Path]; ok && (call.Prefix || call.Method == "") {
			for _, sub := range subs {
				probes = append(probes, facadeProbe{"daytona", sub[0], sub[1]})
			}
			continue
		}
		if call.Prefix || call.Method == "" {
			t.Fatalf("daytona forwards %q with no concrete SDK calls listed in daytonaPrefixCalls", call.Path)
		}
		probes = append(probes, facadeProbe{"daytona", call.Method, call.Path})
	}
	for _, call := range runloop.ToolboxCalls() {
		probes = append(probes, facadeProbe{"runloop", call.Method, call.Path})
	}
	for _, call := range e2b.EnvdCalls() {
		probes = append(probes, facadeProbe{"e2b", call.Method, call.Path})
	}
	return probes
}

// TestFacadeToolboxRoutesExistInToolboxd is plan X2: every path the Daytona,
// Runloop and E2B facades send to toolboxd must reach a real toolboxd route.
// Bad inputs, missing files and missing sessions may still fail; only "no
// such route" (routeMissingHeader) fails the test. Language servers and
// Daytona terminals must answer a clear 501 until they are built.
func TestFacadeToolboxRoutesExistInToolboxd(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	probes := facadeProbes(t)
	if len(probes) < 40 {
		t.Fatalf("only %d probes; the facade inventories look empty", len(probes))
	}
	for _, p := range probes {
		var body *strings.Reader
		if p.method == http.MethodPost {
			body = strings.NewReader("{}")
		} else {
			body = strings.NewReader("")
		}
		req := httptest.NewRequest(p.method, p.path, body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Header().Get(routeMissingHeader) != "" {
			t.Errorf("%s forwards %s %s, but toolboxd has no such route (status %d)", p.facade, p.method, p.path, rr.Code)
			continue
		}
		if isDaytonaLSPPath(p.path) || isDaytonaPTYPath(p.path) {
			if rr.Code != http.StatusNotImplemented {
				t.Errorf("%s %s = %d, want a clear 501", p.method, p.path, rr.Code)
			}
		}
	}
}
