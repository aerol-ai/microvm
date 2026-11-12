package aerolapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
