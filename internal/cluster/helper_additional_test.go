package cluster

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func newAgentControlPlaneHarness(t *testing.T, handler http.Handler, gossipMembers ...Member) *Agent {
	t.Helper()
	server, internalClient := newNodeBoundForwardServer(t, "worker-self", "server-1", handler)

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "server-1", APIURL: server.URL, InternalURL: server.URL, Alive: true, Role: config.NodeRoleServer})
	for _, member := range gossipMembers {
		index.upsert(member)
	}

	return &Agent{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		nodeID:         "worker-self",
		internalClient: internalClient,
		gossip:         &gossipNode{memberIndex: index},
	}
}

func memberIDs(members []Member) []string {
	ids := make([]string, 0, len(members))
	for _, member := range members {
		ids = append(ids, member.NodeID)
	}
	sort.Strings(ids)
	return ids
}

func TestAgentSpecOfUsesControlPlaneAndReturnsDeepCopy(t *testing.T) {
	redacted := &models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		Env:              map[string]string{"A": "1"},
		Mounts:           []models.MountSpec{{Source: "tmpfs", Target: "/workspace"}},
		PlatformVolumes:  []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
		ContainerCommand: []string{"sh", "-c", "echo hi"},
	}
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalPlacementPath+"sb-agent-spec" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
			SandboxID: "sb-agent-spec",
			Placement: Placement{SandboxID: "sb-agent-spec", Version: 7, Spec: redacted},
			Owner:     OwnerInfo{NodeID: "worker-self", IsSelf: true},
		})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	got := agent.SpecOf("sb-agent-spec")
	if got == nil {
		t.Fatal("SpecOf() returned nil, want cloned spec")
	}
	got.Env["A"] = "mutated"
	got.Mounts[0].Target = "/mutated"
	got.PlatformVolumes[0].Path = "/mutated"
	got.ContainerCommand[0] = "bash"

	again := agent.SpecOf("sb-agent-spec")
	if again == nil {
		t.Fatal("SpecOf() returned nil on second read")
	}
	if again.Env["A"] != "1" {
		t.Fatalf("SpecOf() env mutation leaked: %q", again.Env["A"])
	}
	if again.Mounts[0].Target != "/workspace" {
		t.Fatalf("SpecOf() mount mutation leaked: %q", again.Mounts[0].Target)
	}
	if again.PlatformVolumes[0].Path != "/workspace" {
		t.Fatalf("SpecOf() platform volume mutation leaked: %q", again.PlatformVolumes[0].Path)
	}
	if again.ContainerCommand[0] != "sh" {
		t.Fatalf("SpecOf() command mutation leaked: %q", again.ContainerCommand[0])
	}
	if gotVersion := agent.PlacementVersion(); gotVersion != 7 {
		t.Fatalf("PlacementVersion() = %d, want 7", gotVersion)
	}
}

func TestAgentSpecOfReturnsNilOnControlPlaneError(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if got := agent.SpecOf("sb-agent-error"); got != nil {
		t.Fatalf("SpecOf() = %+v, want nil on control-plane error", got)
	}
}

func TestAgentSpecOfReturnsNilWhenPlacementHasNoSpec(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalPlacementPath+"sb-agent-no-spec" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
			SandboxID: "sb-agent-no-spec",
			Placement: Placement{SandboxID: "sb-agent-no-spec", Version: 9},
			Owner:     OwnerInfo{NodeID: "worker-self", IsSelf: true},
		})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if got := agent.SpecOf("sb-agent-no-spec"); got != nil {
		t.Fatalf("SpecOf() = %+v, want nil when placement spec is absent", got)
	}
	if gotVersion := agent.PlacementVersion(); gotVersion != 9 {
		t.Fatalf("PlacementVersion() = %d, want 9 after nil-spec lookup", gotVersion)
	}
}

func TestAgentMembersUsesControlPlaneResponse(t *testing.T) {
	controlPlaneMembers := []Member{{NodeID: "server-control", Alive: true, Role: config.NodeRoleServer}}
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/cluster/members" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"members": controlPlaneMembers})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	got := agent.Members()
	if ids := memberIDs(got); len(ids) != 1 || ids[0] != "server-control" {
		t.Fatalf("Members() ids = %v, want [server-control]", ids)
	}
}

func TestAgentMembersFallsBackToGossipOnControlPlaneError(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}),
		Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker},
		Member{NodeID: "worker-2", Alive: true, Role: config.NodeRoleWorker},
	)

	got := agent.Members()
	if ids := memberIDs(got); len(ids) != 3 || ids[0] != "server-1" || ids[1] != "worker-2" || ids[2] != "worker-self" {
		t.Fatalf("Members() fallback ids = %v, want [server-1 worker-2 worker-self]", ids)
	}
}

func TestAgentMembersFallsBackToGossipWhenControlPlanePayloadHasNoMembers(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/cluster/members" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}),
		Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker},
		Member{NodeID: "worker-2", Alive: true, Role: config.NodeRoleWorker},
	)

	got := agent.Members()
	if ids := memberIDs(got); len(ids) != 3 || ids[0] != "server-1" || ids[1] != "worker-2" || ids[2] != "worker-self" {
		t.Fatalf("Members() fallback ids = %v, want [server-1 worker-2 worker-self]", ids)
	}
}

func TestAgentLeaderReadsControlPlane(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalClusterLeaderPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"leader": "server-1"})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if got := agent.Leader(); got != "server-1" {
		t.Fatalf("Leader() = %q, want server-1", got)
	}
}

func TestAgentLeaderReturnsEmptyOnControlPlaneError(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if got := agent.Leader(); got != "" {
		t.Fatalf("Leader() = %q, want empty string on control-plane error", got)
	}
}

func TestClusterSpecOfReturnsDeepCopy(t *testing.T) {
	fsm := newPlacementFSM()
	payload, err := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "sb-cluster-spec",
		OwnerNodeID: "node-a",
		OwnerAPIURL: "http://node-a",
		Spec: &models.CreateSandboxRequest{
			Image:            "alpine:3.20",
			Env:              map[string]string{"A": "1"},
			Mounts:           []models.MountSpec{{Source: "tmpfs", Target: "/workspace"}},
			PlatformVolumes:  []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
			ContainerCommand: []string{"sh", "-c", "echo hi"},
		},
	})
	if err != nil {
		t.Fatalf("encodeCommand: %v", err)
	}
	if got := fsm.Apply(&raft.Log{Data: payload}); got != nil {
		t.Fatalf("fsm.Apply() = %v, want nil", got)
	}

	cluster := &Cluster{fsm: fsm}
	got := cluster.SpecOf("sb-cluster-spec")
	if got == nil {
		t.Fatal("SpecOf() returned nil, want cloned spec")
	}
	got.Env["A"] = "mutated"
	got.Mounts[0].Target = "/mutated"
	got.PlatformVolumes[0].Path = "/mutated"
	got.ContainerCommand[0] = "bash"

	again := cluster.SpecOf("sb-cluster-spec")
	if again == nil {
		t.Fatal("SpecOf() returned nil on second read")
	}
	if again.Env["A"] != "1" {
		t.Fatalf("SpecOf() env mutation leaked: %q", again.Env["A"])
	}
	if again.Mounts[0].Target != "/workspace" {
		t.Fatalf("SpecOf() mount mutation leaked: %q", again.Mounts[0].Target)
	}
	if again.PlatformVolumes[0].Path != "/workspace" {
		t.Fatalf("SpecOf() platform volume mutation leaked: %q", again.PlatformVolumes[0].Path)
	}
	if again.ContainerCommand[0] != "sh" {
		t.Fatalf("SpecOf() command mutation leaked: %q", again.ContainerCommand[0])
	}
}
