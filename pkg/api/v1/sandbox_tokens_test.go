package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
)

// The handler is thin: bad JSON is a 400, a service refusal keeps its
// status, and a 201 carries the token with Cache-Control: no-store.
func TestCreateSandboxTokenHandler(t *testing.T) {
	h, db := newProxyTestHandler(t, config.Config{})
	createProxySandbox(t, db, "sb-tok", "127.0.0.1", "toolbox-secret")
	call := func(id, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/"+id+"/tokens", strings.NewReader(body))
		req.SetPathValue("id", id)
		rr := httptest.NewRecorder()
		h.createSandboxToken(rr, req)
		return rr
	}
	if rr := call("sb-tok", "{"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON = %d", rr.Code)
	}
	if rr := call("sb-tok", `{}`); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "expires_in is required") {
		t.Fatalf("no lifetime = %d %s", rr.Code, rr.Body.String())
	}
	if rr := call("sb-none", `{"expires_in":"1m"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown sandbox = %d", rr.Code)
	}
	rr := call("sb-tok", `{"expires_in":"1m","methods":["get"]}`)
	var tok models.SandboxToken
	_ = json.Unmarshal(rr.Body.Bytes(), &tok)
	if rr.Code != http.StatusCreated || rr.Header().Get("Cache-Control") != "no-store" || !sandboxtoken.IsToken(tok.Token) ||
		tok.SandboxID != "sb-tok" || strings.Join(tok.Methods, ",") != "GET" {
		t.Fatalf("issue = %d %s", rr.Code, rr.Body.String())
	}
}

// The revoke handler is thin too: an unknown sandbox is a 404, and a 200
// carries the sandbox id and the new not-before.
func TestRevokeSandboxTokensHandler(t *testing.T) {
	h, db := newProxyTestHandler(t, config.Config{})
	createProxySandbox(t, db, "sb-rv", "127.0.0.1", "toolbox-secret")
	call := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes/"+id+"/tokens/revoke", nil)
		req.SetPathValue("id", id)
		rr := httptest.NewRecorder()
		h.revokeSandboxTokens(rr, req)
		return rr
	}
	if rr := call("sb-none"); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown sandbox = %d", rr.Code)
	}
	rr := call("sb-rv")
	var got models.RevokeSandboxTokensResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if rr.Code != http.StatusOK || got.SandboxID != "sb-rv" || got.TokensNotBefore.IsZero() {
		t.Fatalf("revoke = %d %s", rr.Code, rr.Body.String())
	}
	if row, err := db.Get(context.Background(), "sb-rv"); err != nil || row.TokensNotBefore != got.TokensNotBefore.Unix() {
		t.Fatalf("row not-before = %+v %v", row, err)
	}
}
