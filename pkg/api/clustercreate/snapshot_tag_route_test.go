package clustercreate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// snapshotHomeStub answers the snapshot-home index the way a cluster node
// does: a key → node map, plus an optional lookup error. It records every key
// looked up so a test can prove a path never consulted the index.
type snapshotHomeStub struct {
	*clusterStub
	homes     map[string]string
	lookupErr error
	lookups   []string
}

func (s *snapshotHomeStub) SnapshotHomeNode(_ context.Context, key string) (string, bool, error) {
	s.lookups = append(s.lookups, key)
	if s.lookupErr != nil {
		return "", false, s.lookupErr
	}
	node, ok := s.homes[key]
	return node, ok, nil
}

func tenantCtx(owner string) context.Context {
	return controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{ExternalID: "user-" + owner, OwnerRef: owner},
	})
}

// seedCommittedSnapshot writes the catalogue row a snapshot commit leaves on
// its home node: the owner-scoped committed tag, owned by the source sandbox.
func seedCommittedSnapshot(t *testing.T, st *store.Store, owner, name string) string {
	t.Helper()
	tag := docker.SnapshotImageTagForOwner(owner, name)
	if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
		Name:                  name,
		Image:                 tag,
		SourceSandboxID:       "sb-source",
		OwnerRef:              owner,
		CreatedAt:             time.Now(),
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	return tag
}

// UC-21 on a cluster: a snapshot is committed on node-b, and the create naming
// its tag (the SDK passes snap.Image) reaches node-a, which has neither the
// image nor the catalogue row. Before the fix node-a kept the create and pulled
// docker.io/aerolvm-snapshot/<hash> from Docker Hub (operator) or answered
// not-found (tenant). Now node-a forwards the create to node-b, the snapshot's
// home, without a reservation id, the same contract as a node-bound built
// image. Every other outcome keeps today's behaviour.
func TestPrepareRoutesSnapshotTagCreateToHome(t *testing.T) {
	tag := docker.SnapshotImageTagForOwner("tenant-a", "demo")
	homeOnNodeB := map[string]string{cluster.SnapshotImageHomeKey(tag): "node-b"}
	workers := []cluster.Member{
		{NodeID: "node-a", APIURL: "http://node-a", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "node-b", APIURL: "http://node-b", Alive: true, Role: config.NodeRoleWorker},
	}
	nodeB := cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b", InternalURL: "https://node-b:7443"}

	tests := []struct {
		name      string
		self      string
		members   []cluster.Member
		ctx       context.Context
		req       models.CreateSandboxRequest
		homes     map[string]string
		lookupErr error
		selectErr error
		heldHere  bool // node-a's catalogue holds the snapshot (it is the home)

		wantOK         bool
		wantForwardTo  string
		wantStatus     int
		wantCode       string
		wantRetryAfter string
		wantLookups    int
		wantReserve    int
	}{
		{
			name: "operator_create_on_non_home_forwards_to_home", self: "node-a", members: workers,
			ctx: context.Background(), req: models.CreateSandboxRequest{Image: tag}, homes: homeOnNodeB,
			wantForwardTo: "node-b", wantLookups: 1,
		},
		{
			// The router does not authorize: the tenant's ownership is checked
			// on node-b, the only node that holds the catalogue row.
			name: "tenant_create_on_non_home_forwards_to_home", self: "node-a", members: workers,
			ctx: tenantCtx("tenant-a"), req: models.CreateSandboxRequest{Image: tag}, homes: homeOnNodeB,
			wantForwardTo: "node-b", wantLookups: 1,
		},
		{
			name: "tag_without_latest_forwards_to_home", self: "node-a", members: workers,
			ctx: context.Background(), req: models.CreateSandboxRequest{Image: tag[:len(tag)-len(":latest")]}, homes: homeOnNodeB,
			wantForwardTo: "node-b", wantLookups: 1,
		},
		{
			name: "ingress_node_forwards_to_home", self: "ingress-a",
			members: []cluster.Member{
				{NodeID: "ingress-a", APIURL: "http://ingress-a", Alive: true, Role: config.NodeRoleIngress},
				{NodeID: "node-b", APIURL: "http://node-b", Alive: true, Role: config.NodeRoleWorker},
			},
			ctx: context.Background(), req: models.CreateSandboxRequest{Image: tag}, homes: homeOnNodeB,
			wantForwardTo: "node-b", wantLookups: 1,
		},
		{
			// The home node keeps its own create without asking the index, so
			// a stale entry cannot move it and an index outage cannot fail it.
			name: "home_node_keeps_create_without_lookup", self: "node-a", members: workers,
			ctx: tenantCtx("tenant-a"), req: models.CreateSandboxRequest{Image: tag}, homes: homeOnNodeB, heldHere: true,
			lookupErr: errors.New("index down"), wantOK: true,
		},
		{
			name: "home_gone_is_artifact_node_unavailable", self: "node-a", members: workers,
			ctx: context.Background(), req: models.CreateSandboxRequest{Image: tag}, homes: homeOnNodeB,
			selectErr:  fmt.Errorf("%w (node %q)", cluster.ErrArtifactNodeUnavailable, "node-b"),
			wantStatus: http.StatusServiceUnavailable, wantCode: models.ErrorCodeArtifactNodeUnavailable, wantLookups: 1,
		},
		{
			name: "home_drained_or_full_is_retryable", self: "node-a", members: workers,
			ctx: context.Background(), req: models.CreateSandboxRequest{Image: tag}, homes: homeOnNodeB,
			selectErr:  cluster.ErrNoPlacementTarget,
			wantStatus: http.StatusServiceUnavailable, wantRetryAfter: "30", wantLookups: 1,
		},
		{
			name: "index_lookup_error_is_retryable", self: "node-a", members: workers,
			ctx: context.Background(), req: models.CreateSandboxRequest{Image: tag}, lookupErr: errors.New("control plane unreachable"),
			wantStatus: http.StatusServiceUnavailable, wantRetryAfter: "30", wantLookups: 1,
		},
		{
			// Unknown tag: today's behaviour. An operator create stays local;
			// a tenant create is not found.
			name: "unknown_tag_operator_stays_local", self: "node-a", members: workers,
			ctx: context.Background(), req: models.CreateSandboxRequest{Image: tag},
			wantOK: true, wantLookups: 1,
		},
		{
			name: "unknown_tag_tenant_not_found", self: "node-a", members: workers,
			ctx: tenantCtx("tenant-a"), req: models.CreateSandboxRequest{Image: tag},
			wantStatus: http.StatusBadRequest, wantLookups: 1,
		},
		{
			name: "index_names_self_stays_local", self: "node-a", members: workers,
			ctx: context.Background(), req: models.CreateSandboxRequest{Image: tag},
			homes:  map[string]string{cluster.SnapshotImageHomeKey(tag): "node-a"},
			wantOK: true, wantLookups: 1,
		},
		{
			// The caller named the pushed registry copy: any node can start it,
			// so it is placed like any portable image and the index is unused.
			name: "pushed_registry_copy_places_normally", self: "node-a", members: workers,
			ctx: context.Background(), homes: homeOnNodeB,
			req: models.CreateSandboxRequest{
				Image:                 tag,
				ImageDistributionMode: models.ImageDistributionAOCR,
				ImageRegistryRef:      "registry.example.com/snapshots/demo:latest",
			},
			wantForwardTo: "node-b", wantReserve: 1,
		},
		{
			name: "plain_image_never_consults_index", self: "node-a", members: workers,
			ctx: context.Background(), req: models.CreateSandboxRequest{Image: "alpine:3.20"}, homes: homeOnNodeB,
			wantForwardTo: "node-b", wantReserve: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &snapshotHomeStub{
				clusterStub: &clusterStub{
					Noop:         cluster.NewNoop(tc.self, "http://"+tc.self, ""),
					selectTarget: nodeB,
					selectErr:    tc.selectErr,
					members:      tc.members,
				},
				homes:     tc.homes,
				lookupErr: tc.lookupErr,
			}
			svc, st := newCreateService(t, stub, false)
			if tc.heldHere {
				seedCommittedSnapshot(t, st, "tenant-a", "demo")
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil).WithContext(tc.ctx)
			r.Header.Set("Authorization", "Bearer caller-token")
			w := httptest.NewRecorder()
			status := 0
			writer := func(rw http.ResponseWriter, code int, errCode, msg string) {
				status = code
				apihttp.WriteErrorCode(rw, code, errCode, msg)
			}

			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			decision, ok := Prepare(w, r, svc, tc.req, writer, PrepareOptions{Logger: logger})

			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (status %d body %q)", ok, tc.wantOK, w.Code, w.Body.String())
			}
			if tc.wantOK && decision.ReservationID != "" {
				t.Fatalf("ReservationID = %q, want none for a local create", decision.ReservationID)
			}
			if len(stub.lookups) != tc.wantLookups {
				t.Fatalf("index lookups = %v, want %d", stub.lookups, tc.wantLookups)
			}
			if tc.wantLookups > 0 && stub.lookups[0] != tag {
				t.Fatalf("index key = %q, want the canonical tag %q", stub.lookups[0], tag)
			}
			if len(stub.reserveCalls) != tc.wantReserve {
				t.Fatalf("ReserveOnTarget calls = %d, want %d", len(stub.reserveCalls), tc.wantReserve)
			}
			if tc.wantStatus != 0 && status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", status, tc.wantStatus, w.Body.String())
			}
			if tc.wantCode != "" {
				var body models.ErrorResponse
				_ = json.Unmarshal(w.Body.Bytes(), &body)
				if body.Code != tc.wantCode {
					t.Fatalf("error code = %q, want %q", body.Code, tc.wantCode)
				}
			}
			if got := w.Header().Get("Retry-After"); got != tc.wantRetryAfter {
				t.Fatalf("Retry-After = %q, want %q", got, tc.wantRetryAfter)
			}

			if tc.wantForwardTo == "" {
				if stub.forwards != 0 {
					t.Fatalf("ForwardHTTP calls = %d, want 0", stub.forwards)
				}
				return
			}
			if stub.forwards != 1 || stub.lastTarget.NodeID != tc.wantForwardTo {
				t.Fatalf("forwards = %d to %q, want 1 to %q", stub.forwards, stub.lastTarget.NodeID, tc.wantForwardTo)
			}
			if got := r.Header.Get(HeaderTarget); got != tc.wantForwardTo {
				t.Fatalf("%s = %q, want %q", HeaderTarget, got, tc.wantForwardTo)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer caller-token" {
				t.Fatalf("forwarded Authorization = %q, want the caller's token", got)
			}
			if tc.wantReserve > 0 {
				return
			}
			// The snapshot path: a local-only create, pinned to the home.
			if got := r.Header.Get(HeaderID); got != "" {
				t.Fatalf("%s = %q, want none (the home creates without a reservation)", HeaderID, got)
			}
			if len(stub.selectReqs) != 1 || stub.selectReqs[0].RequiredNodeID != "node-b" {
				t.Fatalf("placement requests = %+v, want one pinned to node-b", stub.selectReqs)
			}
			if !strings.Contains(logs.String(), "forwarding snapshot image to the node holding the snapshot") {
				t.Fatalf("router log = %q, want the snapshot forward recorded", logs.String())
			}
		})
	}
}

// The forwarded create arrives at node-b with the caller's identity and the
// target header. node-b accepts it as a local create without consulting the
// index again (no loop), resolves the tag through its own catalogue row, and
// applies the same ownership check a create sent straight to node-b gets: the
// owner boots its snapshot, another tenant guessing the tag gets not-found.
func TestSnapshotTagCreateForwardedToHomeKeepsOwnerChecks(t *testing.T) {
	tag := docker.SnapshotImageTagForOwner("tenant-a", "demo")
	members := []cluster.Member{
		{NodeID: "node-a", APIURL: "http://node-a", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "node-b", APIURL: "http://node-b", Alive: true, Role: config.NodeRoleWorker},
	}
	homes := map[string]string{cluster.SnapshotImageHomeKey(tag): "node-b"}

	for _, tc := range []struct {
		name    string
		caller  string
		wantErr error
	}{
		{name: "owner_boots_its_snapshot", caller: "tenant-a"},
		{name: "other_tenant_guessing_the_tag_is_not_found", caller: "tenant-b", wantErr: store.ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Router: node-a forwards (it does not authorize).
			router := &snapshotHomeStub{
				clusterStub: &clusterStub{
					Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
					selectTarget: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b", InternalURL: "https://node-b:7443"},
					members:      members,
				},
				homes: homes,
			}
			routerSvc, _ := newCreateService(t, router, false)
			req := models.CreateSandboxRequest{Image: tag}
			r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil).WithContext(tenantCtx(tc.caller))
			if _, ok := Prepare(httptest.NewRecorder(), r, routerSvc, req, nil, PrepareOptions{SyncBody: true}); ok || router.forwards != 1 {
				t.Fatalf("router ok=%v forwards=%d, want a forward to node-b", ok, router.forwards)
			}
			var forwarded models.CreateSandboxRequest
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &forwarded); err != nil || forwarded.Image != tag || forwarded.ImageDistributionMode != "" {
				t.Fatalf("forwarded body = %s (%v), want the tag left for the home to resolve", raw, err)
			}

			// Home: node-b receives the forward.
			home := &snapshotHomeStub{
				clusterStub: &clusterStub{Noop: cluster.NewNoop("node-b", "http://node-b", ""), members: members},
				homes:       homes,
			}
			homeSvc, homeStore := newCreateService(t, home, true)
			seedCommittedSnapshot(t, homeStore, "tenant-a", "demo")
			arrived := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil).WithContext(tenantCtx(tc.caller))
			arrived.Header = r.Header.Clone()
			decision, ok := Prepare(httptest.NewRecorder(), arrived, homeSvc, forwarded, nil, PrepareOptions{})
			if !ok || decision.ReservationID != "" {
				t.Fatalf("home ok=%v reservation=%q, want a local create without reservation", ok, decision.ReservationID)
			}
			if len(home.lookups) != 0 || home.forwards != 0 {
				t.Fatalf("home looked up %v and forwarded %d times, want neither (loop guard)", home.lookups, home.forwards)
			}

			resp, err := CreateOnSelectedNode(arrived.Context(), homeSvc, nil, forwarded, "", CreateOptions{})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("CreateOnSelectedNode err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateOnSelectedNode: %v", err)
			}
			if resp.Sandbox.Image != tag || resp.Sandbox.OwnerRef != tc.caller {
				t.Fatalf("sandbox image=%q owner=%q, want %q owned by %q", resp.Sandbox.Image, resp.Sandbox.OwnerRef, tag, tc.caller)
			}
			if !slices.ContainsFunc(home.recordCalls, func(c recordCall) bool { return c.sandboxID == resp.Sandbox.ID }) {
				t.Fatalf("home did not record the placement of %s", resp.Sandbox.ID)
			}
		})
	}
}
