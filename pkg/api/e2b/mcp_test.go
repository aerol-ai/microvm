package e2b

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The E2B SDK's `mcp` option (G12): the create is accepted, port 50005 is
// exposed for the gateway the SDK starts, and only what can never work is
// refused, with a message naming it.
func TestE2BCreateMCPOption(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantStatus  int
		wantExposed bool
		wantMessage string
	}{
		{
			name:        "github server config is accepted and the gateway port exposed",
			body:        `{"templateID":"base","mcp":{"github/acme/tools":{"runCmd":"node server.js","installCmd":"npm ci"}}}`,
			wantStatus:  http.StatusCreated,
			wantExposed: true,
		},
		{
			name:        "an empty object still starts the gateway in both SDKs",
			body:        `{"templateID":"base","mcp":{}}`,
			wantStatus:  http.StatusCreated,
			wantExposed: true,
		},
		{
			name:       "null is the same as leaving the option out",
			body:       `{"templateID":"base","mcp":null}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "a private sandbox is not made public by the option",
			body:       `{"templateID":"base","mcp":{},"network":{"allowPublicTraffic":false}}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:        "a string is refused",
			body:        `{"templateID":"base","mcp":"exa"}`,
			wantStatus:  http.StatusBadRequest,
			wantMessage: mcpOptionNotObject,
		},
		{
			name:        "a list is refused",
			body:        `{"templateID":"base","mcp":["exa"]}`,
			wantStatus:  http.StatusBadRequest,
			wantMessage: mcpOptionNotObject,
		},
		{
			name:        "E2B's default MCP template, unmapped, names the missing gateway",
			body:        `{"templateID":"mcp-gateway","mcp":{"exa":{"apiKey":"k"}}}`,
			wantStatus:  http.StatusNotImplemented,
			wantMessage: "mcp-gateway template is not available",
		},
		{
			name:        "the template without the option stays a plain unknown template",
			body:        `{"templateID":"mcp-gateway"}`,
			wantStatus:  http.StatusBadRequest,
			wantMessage: "unsupported templateID",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, handler := newE2BHandlerTestEnv(t)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(tc.body)))
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantMessage != "" && !strings.Contains(rr.Body.String(), tc.wantMessage) {
				t.Fatalf("body = %s, want it to contain %q", rr.Body.String(), tc.wantMessage)
			}
			if tc.wantStatus != http.StatusCreated {
				return
			}
			var created sandboxResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
				t.Fatalf("decode create: %v", err)
			}
			sandbox, err := svc.GetSandbox(context.Background(), created.SandboxID)
			if err != nil {
				t.Fatalf("GetSandbox: %v", err)
			}
			exposed := false
			for _, p := range sandbox.ExposedPorts {
				if p.Port == mcpGatewayPort {
					exposed = true
					if p.Protocol != models.ExposedPortProtocolHTTP || p.TokenGated() {
						t.Fatalf("gateway port = %+v, want a public http port (the gateway checks its own token)", p)
					}
				}
			}
			if exposed != tc.wantExposed {
				t.Fatalf("port %d exposed = %v, want %v (ports %+v)", mcpGatewayPort, exposed, tc.wantExposed, sandbox.ExposedPorts)
			}
		})
	}
}

// A create with the option must not replay one without it inside the
// replay window: only one of them has the gateway port. Creates without it
// keep the fingerprint (and so the sandbox ID) they had before G12.
func TestE2BCreateFingerprintSeparatesMCP(t *testing.T) {
	plain := sandboxMeta{TemplateID: "base", TimeoutSeconds: 300, OnTimeout: "kill", Secure: true}
	withMCP := plain
	withMCP.MCP = true

	plainJSON, err := createFingerprintPayloadJSON("", "base", models.CreateSandboxRequest{}, plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plainJSON), "mcp") {
		t.Fatalf("payload without the option = %s; it must not change for existing creates", plainJSON)
	}
	mcpJSON, err := createFingerprintPayloadJSON("", "base", models.CreateSandboxRequest{}, withMCP)
	if err != nil {
		t.Fatal(err)
	}
	if string(plainJSON) == string(mcpJSON) {
		t.Fatalf("payloads match (%s); a create with mcp would replay one without", mcpJSON)
	}
}

// Two identical creates with the option inside the replay window give one
// sandbox, and the replayed answer still has its one gateway exposure.
func TestE2BCreateMCPReplayKeepsOneExposure(t *testing.T) {
	svc, _, handler := newE2BHandlerTestEnv(t)
	body := `{"templateID":"base","timeout":120,"mcp":{"github/acme/tools":{"runCmd":"node server.js"}}}`
	ids := make([]string, 2)
	for i := range ids {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body)))
		if rr.Code != http.StatusCreated {
			t.Fatalf("create %d status = %d; body=%s", i, rr.Code, rr.Body.String())
		}
		var created sandboxResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		ids[i] = created.SandboxID
	}
	if ids[0] != ids[1] {
		t.Fatalf("replayed create made a second sandbox: %v", ids)
	}
	sandbox, err := svc.GetSandbox(context.Background(), ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(sandbox.ExposedPorts) != 1 || sandbox.ExposedPorts[0].Port != mcpGatewayPort {
		t.Fatalf("exposed ports = %+v, want exactly the gateway port", sandbox.ExposedPorts)
	}
}

// If exposing the gateway port fails, the create is rolled back and its
// idempotency claim freed, so the client's retry starts clean instead of
// replaying a sandbox the gateway could never be reached on.
func TestE2BCreateMCPExposeFailureRollsBack(t *testing.T) {
	svc, st, handler := newE2BHandlerTestEnv(t)
	execStoreSQL(t, st, `CREATE TRIGGER fail_port_insert BEFORE INSERT ON exposed_ports BEGIN SELECT RAISE(FAIL, 'injected port failure'); END`)

	body := `{"templateID":"base","timeout":120,"mcp":{}}`
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body)))
	if rr.Code == http.StatusCreated || !strings.Contains(rr.Body.String(), "injected port failure") {
		t.Fatalf("status = %d, want the expose error; body=%s", rr.Code, rr.Body.String())
	}
	sandboxes, err := svc.ListSandboxes(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sandboxes) != 0 {
		t.Fatalf("sandboxes after the failed create = %d, want 0 (rolled back)", len(sandboxes))
	}

	execStoreSQL(t, st, `DROP TRIGGER fail_port_insert`)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("retry status = %d, want 201 (the claim was freed); body=%s", rr.Code, rr.Body.String())
	}
}

func TestMCPTemplateError(t *testing.T) {
	storeErr := errors.New("store down")
	cases := []struct {
		name       string
		templateID string
		err        error
		wantStatus int
		wantSame   bool
	}{
		{"unknown mcp-gateway becomes a 501", mcpGatewayTemplate, badRequest(`unsupported templateID "mcp-gateway"`), http.StatusNotImplemented, false},
		{"another unknown template keeps its 400", "other", badRequest(`unsupported templateID "other"`), http.StatusBadRequest, true},
		{"a store error is passed through", mcpGatewayTemplate, storeErr, 0, true},
		{"a non-400 request error is passed through", mcpGatewayTemplate, conflict("busy"), http.StatusConflict, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mcpTemplateError(tc.templateID, tc.err)
			if tc.wantSame && got != tc.err {
				t.Fatalf("got %v, want the original error %v", got, tc.err)
			}
			var reqErr requestError
			if tc.wantStatus != 0 {
				if !errors.As(got, &reqErr) || reqErr.status != tc.wantStatus {
					t.Fatalf("got %#v, want status %d", got, tc.wantStatus)
				}
			}
		})
	}
}

func TestExposeMCPGatewayWithoutService(t *testing.T) {
	h := &handlers{}
	if err := h.exposeMCPGateway(context.Background(), "sb-x", sandboxMeta{MCP: true}); err != nil {
		t.Fatalf("no service: %v", err)
	}
}
