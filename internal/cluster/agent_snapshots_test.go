package cluster

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// TestAgentDelegatesSnapshotHomeToControlPlane proves an agent-role node (no FSM)
// writes the snapshot-home index through the apply channel and reads it back via
// the internal snapshot-node endpoint the server answers from its FSM.
func TestAgentDelegatesSnapshotHomeToControlPlane(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}
	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listen: %v", err)
	}
	serverAPIURL := "http://" + apiListener.Addr().String()
	server, cleanupServer := newTestClusterWithAPI(t, "srv-agent-snap", true, nil, serverAPIURL)
	defer cleanupServer()
	waitForLeader(t, server, 10*time.Second)

	srv := startAgentControlPlaneServerWithSnapshots(t, server, apiListener)
	defer srv.Close()

	agent, cleanupAgent := newTestAgentWithRole(t, "wkr-agent-snap", config.NodeRoleWorker,
		[]string{server.gossip.ml.LocalNode().Address()})
	defer cleanupAgent()
	waitForGossipMember(t, server, "wkr-agent-snap", 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, found, err := agent.SnapshotHomeNode(ctx, "snap-agent"); err != nil || found {
		t.Fatalf("home before register = found=%v err=%v, want not-found", found, err)
	}
	if err := agent.RegisterSnapshotNode(ctx, "snap-agent", "node-x"); err != nil {
		t.Fatalf("agent RegisterSnapshotNode: %v", err)
	}
	var node string
	var found bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if node, found, err = agent.SnapshotHomeNode(ctx, "snap-agent"); err == nil && found {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !found || node != "node-x" {
		t.Fatalf("agent SnapshotHomeNode after register = %q,%v, want node-x/true", node, found)
	}
	if err := agent.ForgetSnapshotNode(ctx, "snap-agent"); err != nil {
		t.Fatalf("agent ForgetSnapshotNode: %v", err)
	}
	// Empty name is a local no-op on the agent (no control-plane hop).
	if _, found, err := agent.SnapshotHomeNode(ctx, ""); err != nil || found {
		t.Fatalf("empty name = found=%v err=%v, want not-found/nil", found, err)
	}
	// A 404 from the control plane reads as "no home" (serve locally); a 500 is
	// surfaced as an error. The server below answers these for reserved names.
	if node, found, err := agent.SnapshotHomeNode(ctx, "snap-404"); err != nil || found || node != "" {
		t.Fatalf("404 name = %q,%v,%v, want not-found/nil", node, found, err)
	}
	if _, _, err := agent.SnapshotHomeNode(ctx, "snap-500"); err == nil {
		t.Fatal("500 name should surface an error")
	}
}

func TestAgentSnapshotNodeValidation(t *testing.T) {
	a := &Agent{}
	ctx := context.Background()
	if err := a.RegisterSnapshotNode(ctx, "", "node-x"); err == nil {
		t.Fatal("RegisterSnapshotNode with empty name should error")
	}
	if err := a.RegisterSnapshotNode(ctx, "snap", ""); err == nil {
		t.Fatal("RegisterSnapshotNode with empty node should error")
	}
	if err := a.ForgetSnapshotNode(ctx, "   "); err != nil {
		t.Fatalf("ForgetSnapshotNode with blank name should be a no-op, got %v", err)
	}
	if _, found, err := a.SnapshotHomeNode(ctx, ""); err != nil || found {
		t.Fatalf("SnapshotHomeNode empty = found=%v err=%v, want not-found/nil", found, err)
	}
}

func startAgentControlPlaneServerWithSnapshots(t *testing.T, c *Cluster, ln net.Listener) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(PublicInternalApplyPath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := c.ApplyEncoded(r.Context(), body); err != nil {
			if err == ErrNotLeader {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc(PublicInternalSnapshotNodePath, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("name") {
		case "snap-404":
			http.Error(w, "no home entry", http.StatusNotFound)
			return
		case "snap-500":
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		node, found, err := c.SnapshotHomeNode(r.Context(), r.URL.Query().Get("name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(SnapshotNodeQueryResponse{NodeID: node, Found: found})
	})
	c.AttachInternalHandler(mux)
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: mux}}
	srv.Start()
	return srv
}
