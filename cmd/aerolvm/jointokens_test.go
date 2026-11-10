package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
)

// fakeJoinTokens plays /v1/cluster/join-tokens.
type fakeJoinTokens struct {
	mu       sync.Mutex
	srv      *httptest.Server
	creates  []map[string]any
	deleted  []string
	refuse   string // POST answers 403 with this error
	noURLs   bool
	listBody string
	domain   string // the answering node's SB_DOMAIN, when set
}

const fakeTokenList = `{"tokens":[
 {"id":"wrk001","role":"worker","created_by":"operator","created_at":"2026-11-07T10:00:00Z","reusable":true,"expired":false,"used_by":[{"node_id":"wkr-1","key_hash":"aa","unix_nano":1},{"node_id":"wkr-2","key_hash":"bb","unix_nano":2}]},
 {"id":"srv001","role":"server","created_by":"node:srv-a","created_at":"2026-11-07T10:00:00Z","expires_at":"2026-11-08T10:00:00Z","reusable":false,"expired":false,"used_by":[{"node_id":"srv-b","key_hash":"cc","unix_nano":3}]},
 {"id":"old001","role":"ingress","created_at":"2026-11-01T10:00:00Z","expires_at":"2026-11-01T12:00:00Z","reusable":false,"expired":true,"used_by":[]}
]}`

func newFakeJoinTokens(t *testing.T) (*harness, *fakeJoinTokens) {
	t.Helper()
	f := &fakeJoinTokens{listBody: fakeTokenList}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+agenttoolstest.Token {
			writeFakeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/cluster/join-tokens":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.creates = append(f.creates, body)
			if f.refuse != "" {
				writeFakeJSON(w, http.StatusForbidden, map[string]string{"error": f.refuse})
				return
			}
			out := map[string]any{
				"token": "abc123.0123456789abcdefghijklmnopqrstuv", "id": "abc123", "role": body["role"], "reusable": body["reusable"],
				"ca_cert_hash": "sha256:9a1c", "join_urls": []string{"https://10.0.0.5:7003", "https://10.0.0.6:7003"},
			}
			if f.noURLs {
				out["join_urls"] = []string{}
			}
			if f.domain != "" {
				out["domain"] = f.domain
			}
			if body["ttl"] == "0" {
				out["warning"] = "this token never expires"
			} else {
				out["expires_at"] = "2026-11-07T12:00:00Z"
			}
			writeFakeJSON(w, http.StatusCreated, out)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/cluster/join-tokens":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(f.listBody))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/cluster/join-tokens/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/cluster/join-tokens/")
			if id == "bad" {
				writeFakeJSON(w, http.StatusBadRequest, map[string]string{"error": "cluster: bad join request: token id \"bad\""})
				return
			}
			f.deleted = append(f.deleted, id)
			writeFakeJSON(w, http.StatusOK, map[string]any{"id": id, "revoked": true})
		default:
			writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "no route"})
		}
	}))
	t.Cleanup(f.srv.Close)
	h := newHarness(t)
	h.env["SB_API_URL"] = f.srv.URL
	return h, f
}

func TestJoinCommandOutputs(t *testing.T) {
	h, f := newFakeJoinTokens(t)
	for _, tc := range []struct {
		args   []string
		golden string
	}{
		{[]string{"join-command"}, "join-command"},
		{[]string{"join-command", "--role", "server", "--ttl", "24h"}, "join-command-server"},
		{[]string{"join-command", "--role", "worker", "--ttl", "0", "--reusable"}, "join-command-never"},
		{[]string{"join-command", "--json"}, "join-command-json"},
	} {
		code := h.run(tc.args...)
		if code != exitOK {
			t.Fatalf("%v = %d %s", tc.args, code, h.stderr.String())
		}
		checkGoldenIn(t, "jointokens", tc.golden+".golden", h.transcript(code))
	}
	want := []map[string]any{
		{"role": "worker", "ttl": "", "reusable": false},
		{"role": "server", "ttl": "24h", "reusable": false},
		{"role": "worker", "ttl": "0", "reusable": true},
		{"role": "worker", "ttl": "", "reusable": false},
	}
	for i, w := range want {
		for k, v := range w {
			if f.creates[i][k] != v {
				t.Fatalf("create %d %s = %v, want %v", i, k, f.creates[i][k], v)
			}
		}
	}
	// The command line is exactly what a new machine runs.
	h.run("join-command")
	if line := strings.TrimSpace(h.stdout.String()); line != "curl -fsSL https://aerolvm.aerol.ai | sudo bash -s -- join https://10.0.0.5:7003 --token abc123.0123456789abcdefghijklmnopqrstuv --ca-cert-hash sha256:9a1c" {
		t.Fatalf("command = %q", line)
	}
}

// TestJoinCommandMixedWithDomain: --role mixed asks for a server token and
// the line adds --role mixed; the cluster's domain comes back from the API,
// so the line carries it with the DNS options and never the Cloudflare
// token itself.
func TestJoinCommandMixedWithDomain(t *testing.T) {
	h, f := newFakeJoinTokens(t)
	f.domain = "cluster.example.com"
	code := h.run("join-command", "--role", "mixed")
	if code != exitOK {
		t.Fatalf("join-command --role mixed = %d %s", code, h.stderr.String())
	}
	checkGoldenIn(t, "jointokens", "join-command-mixed-domain.golden", h.transcript(code))
	if f.creates[0]["role"] != "server" {
		t.Fatalf("create = %v, want a server token", f.creates[0])
	}
	for _, tc := range []struct {
		role, token, node string
	}{
		{"", "worker", ""}, {"Worker", "worker", ""}, {"server", "server", ""}, {"ingress", "ingress", ""},
		{"mixed", "server", "mixed"}, {"server, worker", "server", "server,worker"}, {"ingress,worker", "worker", "ingress,worker"},
		{"worker,worker", "worker", ""},
	} {
		token, node, ok := joinRoles(tc.role)
		if !ok || token != tc.token || node != tc.node {
			t.Fatalf("joinRoles(%q) = %q %q %v, want %q %q", tc.role, token, node, ok, tc.token, tc.node)
		}
	}
	l := joinLine{Installer: "https://i.example", JoinURL: "https://10.0.0.5:7003", Token: "t", Domain: "c.example.com", TLSIssuer: "internal", IngressHost: "in.example.com"}
	if got := l.String(); got != "curl -fsSL https://i.example | sudo bash -s -- --domain c.example.com --tls-issuer internal join https://10.0.0.5:7003 --token t --ingress-advertise-host in.example.com" || l.needsDNSToken() {
		t.Fatalf("internal issuer line = %q", got)
	}
}

func TestJoinCommandRefusals(t *testing.T) {
	h, f := newFakeJoinTokens(t)
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"join-command", "--role", "boss"}, exitUsage, "--role must be worker, ingress, server, mixed"},
		{[]string{"join-command", "--role", "mixed,worker"}, exitUsage, "--role must be worker, ingress, server, mixed"},
		{[]string{"join-command", "--ttl", "soon"}, exitUsage, "--ttl must be a duration"},
		{[]string{"join-command", "--ttl", "-1h"}, exitUsage, "--ttl must be a duration"},
		{[]string{"join-command", "--role", "server", "--ttl", "0"}, exitUsage, "only for worker and ingress"},
		{[]string{"join-command", "--role", "server", "--ttl", "48h"}, exitUsage, "at most 24h"},
		{[]string{"join-command", "extra"}, exitUsage, "unexpected argument"},
		{[]string{"join-command", "--nope"}, exitUsage, "-nope"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Fatalf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}
	if len(f.creates) != 0 {
		t.Fatalf("a refused command reached the server: %v", f.creates)
	}
	// Enterprise mode with plain custody: the server refuses ttl 0; the CLI
	// says how to get a token anyway (eng D5).
	f.refuse = "cluster: SB_ENTERPRISE_MODE refuses never-expiring join tokens unless credential custody is wrapped (sandboxd key wrap)"
	if code := h.run("join-command", "--ttl", "0", "--reusable"); code != exitError || !strings.Contains(h.stderr.String(), "hint: give the token a TTL") {
		t.Fatalf("enterprise ttl 0 = %d %q", code, h.stderr.String())
	}
	f.refuse = "forbidden"
	if code := h.run("join-command"); code != exitError || strings.Contains(h.stderr.String(), "give the token a TTL") {
		t.Fatalf("other refusal = %d %q", code, h.stderr.String())
	}
	f.refuse, f.noURLs = "", true
	if code := h.run("join-command"); code != exitError || !strings.Contains(h.stderr.String(), "no join URL") {
		t.Fatalf("no join URL = %d %q", code, h.stderr.String())
	}
}

func TestGetAndDeleteJoinTokens(t *testing.T) {
	h, f := newFakeJoinTokens(t)
	for _, tc := range []struct {
		args   []string
		golden string
	}{
		{[]string{"get", "jointokens"}, "get-jointokens"},
		{[]string{"get", "jt", "-o", "wide"}, "get-jointokens-wide"},
		{[]string{"get", "join-tokens", "-o", "name"}, "get-jointokens-name"},
		{[]string{"get", "jointoken", "srv001", "-o", "yaml"}, "get-jointoken-yaml"},
		{[]string{"delete", "jointoken", "wrk001", "srv001"}, "delete-jointokens"},
		{[]string{"delete", "jointokens", "wrk001", "--json"}, "delete-jointokens-json"},
	} {
		code := h.run(tc.args...)
		if code != exitOK {
			t.Fatalf("%v = %d %s", tc.args, code, h.stderr.String())
		}
		checkGoldenIn(t, "jointokens", tc.golden+".golden", h.transcript(code))
	}
	if strings.Join(f.deleted, ",") != "wrk001,srv001,wrk001" {
		t.Fatalf("deleted = %v", f.deleted)
	}
	if code := h.run("get", "jointokens", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	var list struct {
		Tokens []map[string]any `json:"tokens"`
	}
	h.jsonOut(&list)
	if len(list.Tokens) != 3 || list.Tokens[0]["id"] != "old001" {
		t.Fatalf("list = %+v", list)
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"get", "jointokens", "nope01"}, exitError, `join token "nope01" not found`},
		{[]string{"get", "jointokens", "-o", "bogus"}, exitUsage, "-o must be wide, json, yaml or name"},
		{[]string{"delete", "jointoken"}, exitUsage, "name at least one join token"},
		{[]string{"delete", "jointoken", "bad"}, exitError, "bad join request"},
		{[]string{"describe", "jointoken", "wrk001"}, exitUsage, "describe does not take jointokens"},
		{[]string{"delete", "widget", "x"}, exitUsage, "or jointoken"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Fatalf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}
	f.listBody = `{"tokens":[]}`
	if code := h.run("get", "jointokens"); code != exitOK || !strings.Contains(h.stderr.String(), "no join tokens") {
		t.Fatalf("empty list = %d %q", code, h.stderr.String())
	}
	f.listBody = `{"tokens":[1]}`
	if code := h.run("get", "jointokens"); code != exitError || !strings.Contains(h.stderr.String(), "unreadable join token") {
		t.Fatalf("bad list = %d %q", code, h.stderr.String())
	}
	f.listBody = `not json`
	if code := h.run("get", "jointokens"); code != exitError {
		t.Fatalf("garbage list = %d", code)
	}
}
