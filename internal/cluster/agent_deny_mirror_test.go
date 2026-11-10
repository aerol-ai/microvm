package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// A worker's deny mirror (agent_deny_mirror.go) and the agent's node routes.

func TestAgentDenyMirrorMergeKeepsTheNewestSet(t *testing.T) {
	var m agentDenyMirror
	added := m.merge(DeniedNodesResponse{Version: 5, Nodes: []NodeDenyRecord{{NodeID: "a"}, {NodeID: ""}}})
	if len(added) != 1 || !m.has("a") || m.cursor() != 5 {
		t.Fatalf("first merge added %v, cursor %d", added, m.cursor())
	}
	// A lagging server's older (or equal) answer never replaces the copy.
	if added := m.merge(DeniedNodesResponse{Version: 5, Nodes: []NodeDenyRecord{{NodeID: "b"}}}); added != nil || m.has("b") {
		t.Fatalf("an equal version was taken: %v", added)
	}
	if added := m.merge(DeniedNodesResponse{Version: 3}); added != nil || !m.has("a") || m.cursor() != 5 {
		t.Fatalf("an older version was taken: %v", added)
	}
	if added := m.merge(DeniedNodesResponse{Version: 9, Nodes: []NodeDenyRecord{{NodeID: "a"}, {NodeID: "b"}}}); strings.Join(added, ",") != "b" {
		t.Fatalf("newer merge added %v, want only the new id", added)
	}
	var nilMirror *agentDenyMirror
	if nilMirror.has("a") || m.has("") {
		t.Fatal("has on nil mirror or empty id")
	}
}

func TestAgentSyncDeniedFromServerTier(t *testing.T) {
	var mu sync.Mutex
	var sinces []string
	reply := func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != PublicInternalDeniedNodesPath {
			return false
		}
		since := r.URL.Query().Get("since")
		mu.Lock()
		sinces = append(sinces, since)
		mu.Unlock()
		switch since {
		case "0":
			_ = json.NewEncoder(w).Encode(DeniedNodesResponse{Version: 7, Nodes: []NodeDenyRecord{{NodeID: "wkr-gone"}}})
		case "7":
			w.WriteHeader(http.StatusNotModified)
		}
		return true
	}
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, reply), Member{NodeID: "wkr-gone", Alive: true, Role: config.NodeRoleWorker})
	index := agent.gossip.currentMemberIndex()
	index.selfID, index.denied = agent.nodeID, agent.deny.has
	ctx := context.Background()
	if agent.IsNodeDenied("wkr-gone") {
		t.Fatal("denied before any poll")
	}
	if err := agent.syncDenied(ctx); err != nil {
		t.Fatal(err)
	}
	if !agent.IsNodeDenied("wkr-gone") || !agent.refuseDeniedPeer("wkr-gone") || agent.refuseDeniedPeer("server-1") {
		t.Fatal("the mirror did not take the server's set")
	}
	if !IsDeniedPeer(agent, "wkr-gone") {
		t.Fatal("IsDeniedPeer on an agent")
	}
	// The poll dropped it from the member view at once; the server stays.
	if _, ok := agent.gossip.lookupMember("wkr-gone"); ok {
		t.Fatal("the deleted node is still in the agent's view")
	}
	if _, ok := agent.gossip.lookupMember("server-1"); !ok {
		t.Fatal("the deny refresh dropped a live server")
	}
	if err := agent.syncDenied(ctx); err != nil {
		t.Fatalf("304 poll: %v", err)
	}
	mu.Lock()
	got := strings.Join(sinces, ",")
	mu.Unlock()
	if got != "0,7" {
		t.Fatalf("polls sent since=%s, want 0,7", got)
	}
	var nilAgent *Agent
	if nilAgent.IsNodeDenied("wkr-gone") {
		t.Fatal("nil agent denied a node")
	}
}

func TestAgentSyncDeniedErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		handler func(w http.ResponseWriter)
		wantErr bool
	}{
		"older server without the route": {func(w http.ResponseWriter) { http.NotFound(w, nil) }, false},
		"server failure":                 {func(w http.ResponseWriter) { http.Error(w, "boom", http.StatusInternalServerError) }, true},
		"unreadable body":                {func(w http.ResponseWriter) { _, _ = w.Write([]byte(`"not an object"`)) }, true},
		"no news":                        {func(w http.ResponseWriter) { _ = json.NewEncoder(w).Encode(DeniedNodesResponse{}) }, false},
	} {
		t.Run(name, func(t *testing.T) {
			capture := &agentControlPlaneCapture{}
			agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != PublicInternalDeniedNodesPath {
					return false
				}
				tc.handler(w)
				return true
			}))
			if err := agent.syncDenied(context.Background()); (err != nil) != tc.wantErr {
				t.Fatalf("syncDenied = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestAgentDenyMirrorLoopRunsUntilClose(t *testing.T) {
	var polls atomic.Int32
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != PublicInternalDeniedNodesPath {
			return false
		}
		polls.Add(1)
		_ = json.NewEncoder(w).Encode(DeniedNodesResponse{Version: 3, Nodes: []NodeDenyRecord{{NodeID: "wkr-x"}}})
		return true
	}))
	agent.startDenyMirror(10 * time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for !agent.IsNodeDenied("wkr-x") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !agent.IsNodeDenied("wkr-x") {
		t.Fatal("the loop never synced")
	}
	if err := agent.Close(); err != nil {
		t.Fatal(err)
	}
	settled := polls.Load()
	time.Sleep(50 * time.Millisecond)
	if polls.Load() > settled+1 {
		t.Fatalf("the loop kept polling after Close: %d then %d", settled, polls.Load())
	}
}

func TestAgentDeleteAndReadNodeThroughServerTier(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasPrefix(r.URL.Path, PublicNodesPath) {
			return false
		}
		id := strings.TrimPrefix(r.URL.Path, PublicNodesPath)
		switch {
		case r.Method == http.MethodDelete && id == "wkr-1":
			_ = json.NewEncoder(w).Encode(NodeDeleteResult{NodeID: id, Denied: true, AlreadyDeleted: r.URL.Query().Get("force") == "true"})
		case r.Method == http.MethodDelete && id == "wkr-busy":
			http.Error(w, `{"error":"`+ErrNodeStillServing.Error()+`"}`, http.StatusConflict)
		case r.Method == http.MethodGet && id == "wkr-1":
			_ = json.NewEncoder(w).Encode(NodeDetail{Member: Member{NodeID: id}, SandboxesOwned: 4, SandboxIDs: strings.Split(r.URL.Query().Get("sandboxes"), ",")})
		default:
			http.Error(w, `{"error":"`+ErrUnknownNode.Error()+`"}`, http.StatusNotFound)
		}
		return true
	}))
	ctx := context.Background()
	if res, err := agent.DeleteNode(ctx, " wkr-1 ", true); err != nil || !res.Denied || !res.AlreadyDeleted {
		t.Fatalf("DeleteNode = %+v %v", res, err)
	}
	if _, err := agent.DeleteNode(ctx, "wkr-busy", false); !errors.Is(err, ErrNodeStillServing) {
		t.Fatalf("busy = %v", err)
	}
	if _, err := agent.DeleteNode(ctx, "wkr-gone", false); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("gone = %v", err)
	}
	if _, err := agent.DeleteNode(ctx, "", false); err == nil {
		t.Fatal("empty id accepted")
	}
	d, err := agent.NodeDetail(ctx, "wkr-1", 25)
	if err != nil || d.SandboxesOwned != 4 || strings.Join(d.SandboxIDs, ",") != "25" {
		t.Fatalf("NodeDetail = %+v %v", d, err)
	}
	if _, err := agent.NodeDetail(ctx, "wkr-gone", 0); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("detail of a gone node = %v", err)
	}
}
