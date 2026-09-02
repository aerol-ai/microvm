package cluster

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestAgentDelegatesPlacementReadWriteToServerControlPlane(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires opening real raft/memberlist sockets")
	}

	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listen: %v", err)
	}
	serverAPIURL := "http://" + apiListener.Addr().String()
	server, cleanupServer := newTestClusterWithAPI(t, "srv-agent-rpc", true, nil, serverAPIURL)
	defer cleanupServer()
	waitForLeader(t, server, 10*time.Second)

	srv := startAgentControlPlaneServer(t, server, apiListener)
	defer srv.Close()

	agent, cleanupAgent := newTestAgentWithRole(t, "wkr-agent-rpc", config.NodeRoleWorker,
		[]string{server.gossip.ml.LocalNode().Address()})
	defer cleanupAgent()

	waitForGossipMember(t, server, "wkr-agent-rpc", 10*time.Second)
	assertNotInRaftConfig(t, server, "wkr-agent-rpc")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := agent.RecordPlacement(ctx, "sb-agent-rpc", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("agent RecordPlacement: %v", err)
	}

	serverOwner, err := server.OwnerOf("sb-agent-rpc")
	if err != nil {
		t.Fatalf("server OwnerOf: %v", err)
	}
	if serverOwner.NodeID != "wkr-agent-rpc" {
		t.Fatalf("server owner = %q, want agent node", serverOwner.NodeID)
	}

	agentOwner, err := agent.OwnerOf("sb-agent-rpc")
	if err != nil {
		t.Fatalf("agent OwnerOf: %v", err)
	}
	if agentOwner.NodeID != "wkr-agent-rpc" || !agentOwner.IsSelf {
		t.Fatalf("agent owner = %+v, want self owner", agentOwner)
	}
}

func TestAgentPlacementVersionUsesObservedReads(t *testing.T) {
	agent := &Agent{}
	agent.observePlacementVersions([]Placement{{SandboxID: "a", Version: 3}, {SandboxID: "b", Version: 2}})
	if got := agent.PlacementVersion(); got != 3 {
		t.Fatalf("PlacementVersion after shard read = %d, want 3", got)
	}
	agent.observePlacementVersion(1)
	if got := agent.PlacementVersion(); got != 3 {
		t.Fatalf("PlacementVersion regressed to %d, want 3", got)
	}
	agent.observePlacementVersion(5)
	if got := agent.PlacementVersion(); got != 5 {
		t.Fatalf("PlacementVersion after point read = %d, want 5", got)
	}
}

func startAgentControlPlaneServer(t *testing.T, c *Cluster, ln net.Listener) *httptest.Server {
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
	mux.HandleFunc(PublicInternalPlacementPath, func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, PublicInternalPlacementPath)
		p, ok := c.PlacementOf(id)
		if !ok {
			http.Error(w, "no placement record", http.StatusNotFound)
			return
		}
		owner, err := c.OwnerOf(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		p.SecretRef = ""
		p.SecretVersion = 0
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: id, Placement: p, Owner: owner})
	})
	c.AttachInternalHandler(mux)
	srv := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: mux},
	}
	srv.Start()
	return srv
}
