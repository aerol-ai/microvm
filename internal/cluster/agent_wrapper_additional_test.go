package cluster

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

type agentControlPlaneCapture struct {
	mu                sync.Mutex
	commands          []command
	recoveryBlobs     []RecoveryBlob
	selectRequests    []SelectPlacementRequest
	shardFilters      []PlacementShardFilter
	pageRequests      []PlacementPageRequest
	removeMemberPaths []string
}

func (c *agentControlPlaneCapture) handler(t *testing.T, extra func(http.ResponseWriter, *http.Request) bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalApplyPath:
			payload, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read apply payload: %v", err)
			}
			cmd, err := decodeCommand(payload)
			if err != nil {
				t.Fatalf("decode apply payload: %v", err)
			}
			c.mu.Lock()
			c.commands = append(c.commands, cmd)
			c.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, PublicInternalRecoveryPath):
			var blob RecoveryBlob
			if err := json.NewDecoder(r.Body).Decode(&blob); err != nil {
				t.Fatalf("decode recovery blob: %v", err)
			}
			c.mu.Lock()
			c.recoveryBlobs = append(c.recoveryBlobs, blob)
			c.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case extra != nil && extra(w, r):
			return
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
	})
}

func (c *agentControlPlaneCapture) appendSelectRequest(req SelectPlacementRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.selectRequests = append(c.selectRequests, req)
}

func (c *agentControlPlaneCapture) appendShardFilter(filter PlacementShardFilter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shardFilters = append(c.shardFilters, filter)
}

func (c *agentControlPlaneCapture) appendPageRequest(req PlacementPageRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pageRequests = append(c.pageRequests, req)
}

func (c *agentControlPlaneCapture) appendRemoveMemberPath(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeMemberPaths = append(c.removeMemberPaths, path)
}

func (c *agentControlPlaneCapture) commandsSnapshot() []command {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]command(nil), c.commands...)
}

func (c *agentControlPlaneCapture) recoveryBlobsSnapshot() []RecoveryBlob {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]RecoveryBlob(nil), c.recoveryBlobs...)
}

func (c *agentControlPlaneCapture) selectRequestsSnapshot() []SelectPlacementRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]SelectPlacementRequest(nil), c.selectRequests...)
}

func (c *agentControlPlaneCapture) shardFiltersSnapshot() []PlacementShardFilter {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]PlacementShardFilter(nil), c.shardFilters...)
}

func (c *agentControlPlaneCapture) pageRequestsSnapshot() []PlacementPageRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]PlacementPageRequest(nil), c.pageRequests...)
}

func (c *agentControlPlaneCapture) removeMemberPathsSnapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.removeMemberPaths...)
}

func TestAgentOwnerOfNameAndSelectPlacement(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	demoPath := PublicInternalPlacementByNamePath + base64.RawURLEncoding.EncodeToString([]byte("demo name"))
	missingPath := PublicInternalPlacementByNamePath + base64.RawURLEncoding.EncodeToString([]byte("missing"))
	orphanPath := PublicInternalPlacementByNamePath + base64.RawURLEncoding.EncodeToString([]byte("orphan"))
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == demoPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-demo",
				Owner:     OwnerInfo{NodeID: "worker-self", APIURL: "http://ignored"},
			})
			return true
		case r.Method == http.MethodGet && r.URL.Path == missingPath:
			http.Error(w, "not found", http.StatusNotFound)
			return true
		case r.Method == http.MethodGet && r.URL.Path == orphanPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: "sb-orphan", Orphaned: true})
			return true
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalSelectPlacementPath:
			var req SelectPlacementRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode select placement request: %v", err)
			}
			capture.appendSelectRequest(req)
			w.Header().Set("Content-Type", "application/json")
			if req.Request.CPU == 99 {
				_ = json.NewEncoder(w).Encode(SelectPlacementResponse{Error: ErrNoPlacementTarget.Error()})
				return true
			}
			_ = json.NewEncoder(w).Encode(SelectPlacementResponse{Target: PlacementTarget{NodeID: "worker-self", APIURL: "http://server", DataPlaneHost: "ignored", InternalURL: "https://ignored"}})
			return true
		default:
			return false
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
	agent.apiURL = "http://self"
	agent.dataPlaneHost = "self-dp"
	agent.internalURL = "https://self-internal"

	if got := agent.SelfNodeID(); got != "worker-self" {
		t.Fatalf("SelfNodeID() = %q, want worker-self", got)
	}
	if got := agent.SelfAPIURL(); got != "http://self" {
		t.Fatalf("SelfAPIURL() = %q, want http://self", got)
	}

	id, owner, err := agent.OwnerOfName("  demo name ")
	if err != nil {
		t.Fatalf("OwnerOfName() error = %v", err)
	}
	if id != "sb-demo" {
		t.Fatalf("OwnerOfName() sandbox id = %q, want sb-demo", id)
	}
	if owner.NodeID != "worker-self" || !owner.IsSelf {
		t.Fatalf("OwnerOfName() owner = %+v, want self owner", owner)
	}
	if _, _, err := agent.OwnerOfName("missing"); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("OwnerOfName(missing) error = %v, want ErrUnknownSandbox", err)
	}
	id, _, err = agent.OwnerOfName("orphan")
	if !errors.Is(err, ErrOrphaned) || id != "sb-orphan" {
		t.Fatalf("OwnerOfName(orphan) = (%q, %v), want (sb-orphan, ErrOrphaned)", id, err)
	}

	target, err := agent.SelectPlacement(capacity.Request{CPU: 2, MemoryMB: 1024})
	if err != nil {
		t.Fatalf("SelectPlacement() error = %v", err)
	}
	if target.NodeID != "worker-self" || target.APIURL != "http://self" || target.DataPlaneHost != "self-dp" || target.InternalURL != "https://self-internal" || !target.IsSelf {
		t.Fatalf("SelectPlacement() target = %+v, want self target metadata rewritten", target)
	}
	if _, err := agent.SelectPlacement(capacity.Request{CPU: 99}); !errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("SelectPlacement(no target) error = %v, want ErrNoPlacementTarget", err)
	}
	requests := capture.selectRequestsSnapshot()
	if len(requests) != 2 || requests[0].Request.CPU != 2 || requests[0].Request.MemoryMB != 1024 {
		t.Fatalf("select placement requests = %+v, want first request footprint preserved", requests)
	}
}

func TestAgentLookupDerivedReadsAndMutationWrappers(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"sb-state":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementLookupResponse{
				SandboxID: "sb-state",
				Placement: Placement{
					SandboxID:         "sb-state",
					Version:           12,
					SecretRef:         "cluster-secret://sandbox/sb-state/v1",
					SecretVersion:     3,
					ExposedPortRoutes: map[int]ExposedPortRoute{5432: {Protocol: "tcp", HostPort: 22432, PublicURL: "tcp://sandbox.example.com:22432"}},
				},
				Owner: OwnerInfo{NodeID: "server-1", APIURL: "http://server-1"},
			})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementPath+"missing":
			http.Error(w, "not found", http.StatusNotFound)
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalDrainStatePath+"node-a":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(DrainStateResponse{Drained: true})
			return true
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalDrainStatePath+"node-b":
			http.Error(w, "boom", http.StatusInternalServerError)
			return true
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/cluster/members/"):
			capture.appendRemoveMemberPath(r.URL.RequestURI())
			if strings.HasSuffix(r.URL.Path, "/missing") {
				http.Error(w, ErrUnknownMember.Error(), http.StatusNotFound)
				return true
			}
			w.WriteHeader(http.StatusNoContent)
			return true
		default:
			return false
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	placement, ok := agent.PlacementOf("sb-state")
	if !ok || placement.SandboxID != "sb-state" || placement.Version != 12 {
		t.Fatalf("PlacementOf() = (%+v, %v), want sb-state placement and true", placement, ok)
	}
	if got := agent.PlacementVersion(); got != 12 {
		t.Fatalf("PlacementVersion() = %d, want 12", got)
	}
	secrets := agent.SecretsOf("sb-state")
	if secrets.Ref != "cluster-secret://sandbox/sb-state/v1" || secrets.Version != 3 {
		t.Fatalf("SecretsOf() = %+v, want replicated secret handle", secrets)
	}
	routes := agent.ExposedPortsOf("sb-state")
	if routes[5432].HostPort != 22432 || routes[5432].Protocol != "tcp" {
		t.Fatalf("ExposedPortsOf() = %+v, want tcp route metadata", routes)
	}
	if placement, ok := agent.PlacementOf("missing"); ok || placement.SandboxID != "" {
		t.Fatalf("PlacementOf(missing) = (%+v, %v), want zero placement and false", placement, ok)
	}
	if !agent.IsNodeDrained("node-a") {
		t.Fatal("IsNodeDrained(node-a) = false, want true")
	}
	if agent.IsNodeDrained("node-b") {
		t.Fatal("IsNodeDrained(node-b) = true, want false on control-plane error")
	}

	ctx := context.Background()
	if err := agent.RecordPlacement(ctx, "sb-record", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement() error = %v", err)
	}
	if err := agent.ClaimOrphan(ctx, "sb-claim", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("ClaimOrphan() error = %v", err)
	}
	if err := agent.UpsertSpec(ctx, "sb-upsert", &models.CreateSandboxRequest{Image: "alpine:3.20", Name: "named"}, PlacementSecrets{}); err != nil {
		t.Fatalf("UpsertSpec() error = %v", err)
	}
	if err := agent.AddExposedPort(ctx, "sb-port", 8080, ExposedPortRoute{Protocol: "http", PublicURL: "https://sandbox.example.com"}); err != nil {
		t.Fatalf("AddExposedPort() error = %v", err)
	}
	if err := agent.RemoveExposedPort(ctx, "sb-port", 8080); err != nil {
		t.Fatalf("RemoveExposedPort() error = %v", err)
	}
	if err := agent.DeletePlacement(ctx, "sb-delete"); err != nil {
		t.Fatalf("DeletePlacement() error = %v", err)
	}
	if err := agent.ReserveOnTarget(ctx, "sb-reserve", PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", DataPlaneHost: "dp-a"}, nil, PlacementSecrets{}, time.Minute); err != nil {
		t.Fatalf("ReserveOnTarget() error = %v", err)
	}
	if err := agent.CancelReservation(ctx, "sb-reserve"); err != nil {
		t.Fatalf("CancelReservation() error = %v", err)
	}
	if err := agent.SetNodeDrainState(ctx, "node-a", true); err != nil {
		t.Fatalf("SetNodeDrainState() error = %v", err)
	}
	if err := agent.SetNodeDrainState(ctx, "", true); err == nil {
		t.Fatal("SetNodeDrainState() accepted empty node id")
	}
	if err := agent.RemoveMember(ctx, "node-a", true); err != nil {
		t.Fatalf("RemoveMember() error = %v", err)
	}
	if err := agent.RemoveMember(ctx, "missing", false); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("RemoveMember(missing) error = %v, want ErrUnknownMember", err)
	}
	encoded, err := encodeCommand(command{Op: opDelete, SandboxID: "sb-encoded"})
	if err != nil {
		t.Fatalf("encodeCommand: %v", err)
	}
	if err := agent.ApplyEncoded(ctx, encoded); err != nil {
		t.Fatalf("ApplyEncoded() error = %v", err)
	}
	if err := agent.ApplyEncoded(ctx, []byte("not-json")); err == nil {
		t.Fatal("ApplyEncoded() accepted invalid payload")
	}

	// Payloads ride inline in the raft command — the agent must never push
	// a recovery blob to the control plane. The capture arm stays as a
	// tripwire: any PUT to the recovery path lands here.
	if blobs := capture.recoveryBlobsSnapshot(); len(blobs) != 0 {
		t.Fatalf("recovery blobs = %+v, want none (inline-only recovery)", blobs)
	}
	cmds := capture.commandsSnapshot()
	if len(cmds) != 10 {
		t.Fatalf("captured commands = %d, want 10", len(cmds))
	}
	var upsert command
	seen := make(map[opCode]int)
	for _, cmd := range cmds {
		seen[cmd.Op]++
		if cmd.Op == opUpsertSpec {
			upsert = cmd
		}
	}
	for _, op := range []opCode{opPlace, opClaimOrphan, opUpsertSpec, opAddExposedPort, opRemoveExposedPort, opDelete, opReserve, opCancelReserve, opSetNodeDrainState} {
		if seen[op] == 0 {
			t.Fatalf("captured commands missing op %d: %+v", op, cmds)
		}
	}
	if upsert.Spec == nil || upsert.Spec.Name != "named" {
		t.Fatalf("upsert command = %+v, want inline spec (payloads ride the raft entry)", upsert)
	}
	paths := capture.removeMemberPathsSnapshot()
	if len(paths) != 2 || paths[0] != "/v1/cluster/members/node-a?force=true" || paths[1] != "/v1/cluster/members/missing" {
		t.Fatalf("remove member paths = %v, want force path then missing path", paths)
	}
}

func TestAgentPlacementCollectionsUseControlPlaneAndFallbackCache(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	allPlacements := []Placement{{SandboxID: "sb-a", Version: 21}, {SandboxID: "sb-b", Version: 18}}
	shardPlacements := []Placement{{SandboxID: "sb-shard", Version: 22}}
	pagePlacements := []Placement{{SandboxID: "sb-page", Version: 23}}
	failAllReads := false
	failShardQuery := false
	agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == PublicInternalPlacementsPath:
			if failAllReads {
				http.Error(w, "boom", http.StatusInternalServerError)
				return true
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(allPlacements)
			return true
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalPlacementsQueryPath:
			var filter PlacementShardFilter
			if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
				t.Fatalf("decode shard filter: %v", err)
			}
			capture.appendShardFilter(filter)
			if failShardQuery {
				http.Error(w, "boom", http.StatusInternalServerError)
				return true
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(shardPlacements)
			return true
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalPlacementsPagePath:
			var req PlacementPageRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode placement page request: %v", err)
			}
			capture.appendPageRequest(req)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PlacementPageResponse{Placements: pagePlacements, NextPageToken: "next-page"})
			return true
		default:
			return false
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	if got := agent.Placements(); len(got) != 2 || got[0].SandboxID != "sb-a" {
		t.Fatalf("Placements() = %+v, want control-plane placements", got)
	}
	if got := agent.PlacementVersion(); got != 21 {
		t.Fatalf("PlacementVersion() = %d, want 21 after full placements read", got)
	}

	filter := PlacementShardFilter{ShardCount: 32, Shards: []int{7, 2, 7}}
	if got := agent.PlacementsForShards(filter); len(got) != 1 || got[0].SandboxID != "sb-shard" {
		t.Fatalf("PlacementsForShards() = %+v, want shard placement", got)
	}
	failShardQuery = true
	if got := agent.PlacementsForShards(filter); len(got) != 1 || got[0].SandboxID != "sb-shard" {
		t.Fatalf("PlacementsForShards() fallback = %+v, want cached shard placement", got)
	}
	failAllReads = true
	if got := agent.Placements(); len(got) != 2 || got[0].SandboxID != "sb-a" {
		t.Fatalf("Placements() fallback = %+v, want cached full placement view", got)
	}
	page := agent.PlacementPage(PlacementPageRequest{})
	if !page.Authoritative || len(page.Placements) != 1 || page.Placements[0].SandboxID != "sb-page" || page.NextPageToken != "next-page" {
		t.Fatalf("PlacementPage() = %+v, want authoritative paged response", page)
	}
	filters := capture.shardFiltersSnapshot()
	if len(filters) != 2 || filters[0].ShardCount != 32 || len(filters[0].Shards) != 2 {
		t.Fatalf("shard filters = %+v, want normalized deduplicated filter", filters)
	}
	pages := capture.pageRequestsSnapshot()
	if len(pages) != 1 || pages[0].Limit != DefaultPlacementPageLimit {
		t.Fatalf("page requests = %+v, want normalized default limit", pages)
	}
}

func TestAgentMiscWrappers(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cluster-Forwarded") != "1" {
			t.Fatalf("forwarded request missing loop-detection header")
		}
		_, _ = w.Write([]byte("forwarded"))
	}))
	defer target.Close()

	agent := &Agent{
		publicProxies:  newProxyCache(defaultPublicTransport),
		internalServer: &internalServer{},
		placementCache: []Placement{{SandboxID: "sb-cache"}},
		shardCache: map[string][]Placement{
			placementShardFilterCacheKey(PlacementShardFilter{}): {{SandboxID: "sb-cache"}},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-cache", nil)
	rr := httptest.NewRecorder()
	agent.ForwardHTTP(Endpoint{APIURL: target.URL}, rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "forwarded" {
		t.Fatalf("ForwardHTTP() = (%d, %q), want (200, forwarded)", rr.Code, rr.Body.String())
	}

	agent.AttachInternalHandler(http.NotFoundHandler())
	if agent.internalServer.extra.Load() == nil {
		t.Fatal("AttachInternalHandler() did not install the extra handler")
	}
	if got := agent.SubscribePlacement(context.Background()); got != nil {
		t.Fatalf("SubscribePlacement() = %v, want nil", got)
	}
	cached := agent.cachedPlacements()
	if len(cached) != 1 || cached[0].SandboxID != "sb-cache" {
		t.Fatalf("cachedPlacements() = %+v, want cached placement copy", cached)
	}
	cached[0].SandboxID = "mutated"
	if agent.placementCache[0].SandboxID != "sb-cache" {
		t.Fatalf("cachedPlacements() did not deep-clone: %+v", agent.placementCache)
	}
}
