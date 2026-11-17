package aerolapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// fakeServer answers like sandboxd's admin API and records each call.
func fakeServer(t *testing.T) (*Client, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" && r.URL.Path != "/ready" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/ready":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/v1/cluster/leader":
			_, _ = w.Write([]byte(`{"leader":"s0"}`))
		case r.URL.Path == "/v1/cluster/join-tokens":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["reusable"] != false || body["role"] != "worker" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"token":"abc.def","ca_cert_hash":"sha256:1","join_urls":["https://s0:7003"]}`))
		case r.URL.Path == "/v1/cluster/nodes/w1":
			_, _ = w.Write([]byte(`{"node_id":"w1","alive":true,"capacity":{"cpu_budget":8,"reserved_cpu":3,"memory_budget_mb":1000,"reserved_memory_mb":1200}}`))
		case r.URL.Path == "/v1/cluster/nodes/nope":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"cluster: unknown node"}`))
		case r.URL.Path == "/v1/cluster/members":
			_, _ = w.Write([]byte(`{"members":[{"node_id":"w1"}]}`))
		case r.URL.Path == "/v1/cluster/nodes/w1/evacuate":
			_, _ = w.Write([]byte(`{"moved":["sb-1"],"remaining_movable":0,"done":true}`))
		case r.URL.Path == upgradewire.ClusterUpgradePath && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == upgradewire.ClusterUpgradePath && r.Method == http.MethodPost:
			if r.URL.Query().Get("driver") != "operator" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"kubernetes_managed","reason":"the operator upgrades it"}`))
				return
			}
			var req upgradewire.ApplyRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(upgradewire.Rollout{TargetVersion: req.Version, Source: req.Source})
		case r.URL.Path == upgradewire.ClusterUpgradeRollbackPath:
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL+"/", "tok"), &calls
}

func TestClient(t *testing.T) {
	c, calls := fakeServer(t)
	ctx := context.Background()
	if !c.Ready(ctx) {
		t.Fatal("not ready")
	}
	if l, err := c.Leader(ctx); err != nil || l != "s0" {
		t.Fatalf("leader = %q %v", l, err)
	}
	if err := c.Adopt(ctx); err != nil {
		t.Fatal(err)
	}
	tok, err := c.MintJoinToken(ctx, "worker", "30m", "op")
	if err != nil || tok.Token != "abc.def" || tok.JoinURLs[0] != "https://s0:7003" {
		t.Fatalf("token = %+v %v", tok, err)
	}
	n, err := c.GetNode(ctx, "w1")
	if err != nil || n.Capacity.FreeCPU() != 5 || n.Capacity.FreeMemoryMB() != 0 {
		t.Fatalf("node = %+v %v", n, err)
	}
	if _, err := c.GetNode(ctx, "nope"); !IsStatus(err, http.StatusNotFound) || !strings.Contains(err.Error(), "unknown node") {
		t.Fatalf("missing node = %v", err)
	}
	if m, err := c.Members(ctx); err != nil || len(m) != 1 {
		t.Fatalf("members = %v %v", m, err)
	}
	for _, f := range []func(context.Context, string) error{c.Cordon, c.Uncordon, c.Gone} {
		if err := f(ctx, "w1"); err != nil {
			t.Fatal(err)
		}
	}
	if res, err := c.Evacuate(ctx, "w1", EvacuateRequest{StopRemaining: true}); err != nil || !res.Done || res.Moved[0] != "sb-1" {
		t.Fatalf("evacuate = %+v %v", res, err)
	}
	if err := c.DeleteNode(ctx, "w1", true); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteNode(ctx, "nope", false); err != nil {
		t.Fatalf("deleting a node that is gone already = %v", err)
	}
	if ro, err := c.Rollout(ctx); err != nil || ro != nil {
		t.Fatalf("no rollout = %v %v", ro, err)
	}
	ro, err := c.ApplyImages(ctx, "v0.7.2", upgradewire.ApplyRequest{Files: map[string]string{"x": "y"}})
	if err != nil || ro.TargetVersion != "v0.7.2" || ro.Source != upgradewire.SourceImages {
		t.Fatalf("apply = %+v %v", ro, err)
	}
	if err := c.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /v1/cluster/nodes/w1/cordon", "POST /v1/cluster/upgrade?driver=operator", "DELETE /v1/cluster/nodes/w1?force=true"}
	joined := strings.Join(*calls, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Fatalf("calls lack %q:\n%s", w, joined)
		}
	}
	// A refusal keeps its code and reason.
	bad := New(c.BaseURL, "wrong")
	err = bad.Adopt(ctx)
	if !IsStatus(err, http.StatusUnauthorized) || IsCode(err, "x") {
		t.Fatalf("unauthorized = %v", err)
	}
	e := &Error{Status: 409, Code: "kubernetes_managed", Reason: "the operator upgrades it"}
	if !strings.Contains(e.Error(), "kubernetes_managed: the operator") {
		t.Fatal(e.Error())
	}
	if (&Client{BaseURL: "http://127.0.0.1:1"}).Ready(ctx) {
		t.Fatal("nothing listens there")
	}
}

// A server that stops answering holds a quick call CallTimeout, not the
// HTTP client's minutes; an evacuate pass, which may take minutes, is
// bound only by the HTTP client (review R3).
func TestCallTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/cluster/nodes/w1/evacuate" {
			time.Sleep(150 * time.Millisecond)
			_, _ = w.Write([]byte(`{"done":true}`))
			return
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	c := New(srv.URL, "tok")
	if c.CallTimeout != DefaultCallTimeout || c.HTTP.Timeout != EvacuateTimeout {
		t.Fatalf("defaults: call %s, http %s", c.CallTimeout, c.HTTP.Timeout)
	}
	c.CallTimeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := c.GetNode(context.Background(), "w1"); err == nil {
		t.Fatal("a call to a server that never answers returned no error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the call waited %s", d)
	}
	res, err := c.Evacuate(context.Background(), "w1", EvacuateRequest{})
	if err != nil || !res.Done {
		t.Fatalf("an evacuate pass longer than CallTimeout: %+v %v", res, err)
	}
	// A zero CallTimeout (a hand-made Client) leaves the call to ctx.
	c.CallTimeout = 0
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if c.Ready(ctx) {
		t.Fatal("ready from a server that never answers")
	}
}

// A credential the server refuses with 401 is sent once more as Fallback,
// with the same body: servers made before and after enterprise mode was
// turned on take different ones. Any other refusal, or a fallback equal to
// the token, is not retried.
func TestFallbackCredential(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		seen = append(seen, auth+" "+string(body))
		switch {
		case r.URL.Path == "/v1/cluster/nodes/busy/cordon":
			w.WriteHeader(http.StatusServiceUnavailable)
		case auth == "new":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "old")
	c.Fallback = "new"
	if _, err := c.MintJoinToken(context.Background(), "worker", "10m", "op"); err != nil {
		t.Fatalf("mint with a refused token and a good fallback: %v", err)
	}
	if len(seen) != 2 || !strings.HasPrefix(seen[0], "old {") || seen[1] != "new"+seen[0][len("old"):] {
		t.Fatalf("calls = %q: want the token, then the fallback with the same body", seen)
	}
	seen = nil
	if err := c.Cordon(context.Background(), "busy"); !IsStatus(err, http.StatusServiceUnavailable) || len(seen) != 1 {
		t.Fatalf("a 503 was retried: %v %q", err, seen)
	}
	seen = nil
	c.Token, c.Fallback = "bad", "bad"
	if err := c.WhoAmI(context.Background()); !IsStatus(err, http.StatusUnauthorized) || len(seen) != 1 {
		t.Fatalf("the same credential was sent twice: %v %q", err, seen)
	}
	seen = nil
	c.Fallback = ""
	if err := c.WhoAmI(context.Background()); !IsStatus(err, http.StatusUnauthorized) || len(seen) != 1 {
		t.Fatalf("no fallback: %v %q", err, seen)
	}
}

// The token routes the operator's own API token uses.
func TestTokenRoutes(t *testing.T) {
	var calls []string
	created := `{"id":"tok_1","name":"aerolvm-operator-1","role":"admin","team":"*","created_at":"2026-11-17T12:00:00Z","expires_at":"2026-12-17T12:00:00Z","token":"avm_s"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.Path+" "+string(body))
		switch {
		case r.Method == http.MethodPost && strings.Contains(string(body), `"name":"empty"`):
			_, _ = w.Write([]byte(`{"id":"tok_2"}`))
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(created))
		case r.URL.Path == "/v1/tokens/tok_gone":
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/v1/tokens/tok_err":
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/whoami":
			_, _ = w.Write([]byte(`{"principal":"token:tok_1"}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	got, err := c.CreateToken(context.Background(), "aerolvm-operator-1", "admin", "*", "720h0m0s")
	if err != nil || got.ID != "tok_1" || got.Token != "avm_s" || !got.ExpiresAt.Equal(time.Date(2026, 12, 17, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("create = %+v %v", got, err)
	}
	var req map[string]string
	if err := json.Unmarshal([]byte(strings.SplitN(calls[0], " ", 3)[2]), &req); err != nil ||
		req["name"] != "aerolvm-operator-1" || req["role"] != "admin" || req["team"] != "*" || req["expires_in"] != "720h0m0s" {
		t.Fatalf("create body = %v %v", req, err)
	}
	if _, err := c.CreateToken(context.Background(), "empty", "admin", "*", "1h"); err == nil {
		t.Fatal("a created token without its secret was taken")
	}
	for id, ok := range map[string]bool{"tok_1": true, "tok_gone": true, "tok_err": false} {
		if err := c.RevokeToken(context.Background(), id); (err == nil) != ok {
			t.Errorf("revoke %s: %v", id, err)
		}
	}
	if err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A server that refuses the fallback as an admin token sent from off its
// own pod (SB_PAT_SCOPE=host) does not get it again from this client
// (review S1).
func TestFallbackStopsAfterAHostScopeRefusal(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		seen = append(seen, auth)
		w.WriteHeader(http.StatusUnauthorized)
		if auth == "pat" {
			_, _ = w.Write([]byte(`{"error":"the operator token works only on this host; sign in with ` + "`aerolvm login --sso`" + ` or use a named token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"unauthorized","reason":"unknown_or_revoked"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	c.Fallback = "pat"
	for i := 0; i < 3; i++ {
		_ = c.WhoAmI(context.Background())
	}
	if strings.Join(seen, ",") != "tok,pat,tok,tok" {
		t.Fatalf("sent %q: the admin token went again after the server refused it as off-host", seen)
	}
}

// Any other refusal of the fallback (an unknown token, a server catching
// up) does not stop the next call from sending it.
func TestFallbackKeptAfterAnotherRefusal(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","reason":"unknown_or_revoked"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	c.Fallback = "pat"
	_ = c.WhoAmI(context.Background())
	_ = c.WhoAmI(context.Background())
	if strings.Join(seen, ",") != "tok,pat,tok,pat" {
		t.Fatalf("sent %q", seen)
	}
}
