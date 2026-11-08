package clustercreate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// noPushDocker satisfies service.SnapshotPushDocker. The router never pushes;
// the pusher is attached so the router builds registry refs the way a node
// with SB_SNAPSHOT_PUSH_ENABLED does.
type noPushDocker struct{}

func (noPushDocker) PushImage(context.Context, docker.PushImageRequest) (string, error) {
	return "", errors.New("router does not push")
}

func attachRouterPusher(t *testing.T, svc *service.Service) {
	t.Helper()
	pat := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(pat, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	pusher, err := service.NewSnapshotPusher(service.SnapshotPushConfig{
		Enabled: true, Host: "aocr.test", ClusterID: "cluster-7", PATPath: pat, TagSuffix: "--ttl-1h",
	}, noPushDocker{}, nil)
	if err != nil {
		t.Fatalf("NewSnapshotPusher: %v", err)
	}
	svc.AttachSnapshotPusher(pusher, nil)
}

// UC-459 on cluster-hetero-lite: a snapshot is committed on worker node-b and
// a create names it right away. The create reaches the ingress, which holds no
// snapshot rows, so it built the registry ref and placed the create on any
// worker. The push to the registry was still running (it landed 170 ms after
// the pull), so the worker answered `failed to resolve reference ... not
// found`. While a snapshot's image is only on its home (the local-only key),
// a create by its name now goes to the home, pinned, without a reservation.
// Every other outcome keeps today's path.
func TestPrepareRoutesUnpushedSnapshotNameCreateToHome(t *testing.T) {
	const name = "gym-start"
	ingressMembers := []cluster.Member{
		{NodeID: "ingress-a", APIURL: "http://ingress-a", Alive: true, Role: config.NodeRoleIngress},
		{NodeID: "node-b", APIURL: "http://node-b", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "node-c", APIURL: "http://node-c", Alive: true, Role: config.NodeRoleWorker},
	}
	nodeC := cluster.PlacementTarget{NodeID: "node-c", APIURL: "http://node-c", InternalURL: "https://node-c:7443"}
	nodeB := cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b", InternalURL: "https://node-b:7443"}
	localOnlyOnB := func(owner string) map[string]string {
		return map[string]string{cluster.SnapshotLocalOnlyKey(owner, name): "node-b"}
	}

	tests := []struct {
		name      string
		ctx       context.Context
		owner     string
		req       models.CreateSandboxRequest
		homes     map[string]string
		lookupErr error
		heldHere  bool

		wantOK        bool
		wantForwardTo string
		wantReserve   int
		wantLookups   []string
	}{
		{
			name: "operator_create_by_name_goes_to_home", ctx: context.Background(),
			req: models.CreateSandboxRequest{Image: name}, homes: localOnlyOnB(""),
			wantForwardTo: "node-b", wantLookups: []string{cluster.SnapshotLocalOnlyKey("", name)},
		},
		{
			// The key is the caller's: the home checks the owner on arrival.
			name: "tenant_create_by_name_goes_to_home", ctx: tenantCtx("tenant-a"), owner: "tenant-a",
			req: models.CreateSandboxRequest{Image: name}, homes: localOnlyOnB("tenant-a"),
			wantForwardTo: "node-b", wantLookups: []string{cluster.SnapshotLocalOnlyKey("tenant-a", name)},
		},
		{
			// Another tenant's same-named snapshot is not this caller's.
			name: "other_tenants_entry_is_not_used", ctx: tenantCtx("tenant-b"),
			req: models.CreateSandboxRequest{Image: name}, homes: localOnlyOnB("tenant-a"),
			wantForwardTo: "node-c", wantReserve: 1, wantLookups: []string{cluster.SnapshotLocalOnlyKey("tenant-b", name)},
		},
		{
			// Pushed: the home dropped the key, so the create is placed like
			// any portable image and pulls the registry copy.
			name: "pushed_snapshot_places_anywhere", ctx: context.Background(),
			req:           models.CreateSandboxRequest{Image: name},
			wantForwardTo: "node-c", wantReserve: 1, wantLookups: []string{cluster.SnapshotLocalOnlyKey("", name)},
		},
		{
			// A read error must not fail every create of an untagged image:
			// routing falls back to today's path.
			name: "lookup_error_keeps_todays_path", ctx: context.Background(),
			req: models.CreateSandboxRequest{Image: name}, homes: localOnlyOnB(""), lookupErr: errors.New("control plane unreachable"),
			wantForwardTo: "node-c", wantReserve: 1, wantLookups: []string{cluster.SnapshotLocalOnlyKey("", name)},
		},
		{
			// This node holds the snapshot: it resolves the name itself and
			// never asks the index.
			name: "node_holding_the_snapshot_never_asks", ctx: context.Background(),
			req: models.CreateSandboxRequest{Image: name}, homes: localOnlyOnB(""), heldHere: true,
			wantOK: true,
		},
		{
			name: "tagged_image_never_asks", ctx: context.Background(),
			req: models.CreateSandboxRequest{Image: "alpine:3.20"}, homes: localOnlyOnB(""),
			wantForwardTo: "node-c", wantReserve: 1,
		},
		{
			// The caller named the registry copy: any node can start it.
			name: "named_registry_copy_never_asks", ctx: context.Background(), homes: localOnlyOnB(""),
			req: models.CreateSandboxRequest{
				Image:                 name,
				ImageDistributionMode: models.ImageDistributionAOCR,
				ImageRegistryRef:      "registry.example.com/snapshots/gym-start:latest",
			},
			wantForwardTo: "node-c", wantReserve: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := nodeC
			if tc.wantForwardTo == "node-b" {
				target = nodeB
			}
			self := "ingress-a"
			members := ingressMembers
			if tc.heldHere {
				// The home itself, a worker that can own the create.
				self = "node-b"
				members = []cluster.Member{{NodeID: "node-b", APIURL: "http://node-b", Alive: true, Role: config.NodeRoleWorker}}
			}
			stub := &snapshotHomeStub{
				clusterStub: &clusterStub{
					Noop:         cluster.NewNoop(self, "http://"+self, ""),
					selectTarget: target,
					members:      members,
				},
				homes:     tc.homes,
				lookupErr: tc.lookupErr,
			}
			svc, st := newCreateService(t, stub, false)
			attachRouterPusher(t, svc)
			if tc.heldHere {
				seedCommittedSnapshot(t, st, tc.owner, name)
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil).WithContext(tc.ctx)
			r.Header.Set("Authorization", "Bearer caller-token")
			w := httptest.NewRecorder()
			writer := func(rw http.ResponseWriter, code int, errCode, msg string) {
				apihttp.WriteErrorCode(rw, code, errCode, msg)
			}
			_, ok := Prepare(w, r, svc, tc.req, writer, PrepareOptions{SyncBody: true})

			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (status %d body %q)", ok, tc.wantOK, w.Code, w.Body.String())
			}
			if tc.wantForwardTo == "node-b" {
				// Pinned to the home: the body still names the snapshot for the
				// home to resolve, not a registry ref it would have to pull; no
				// reservation id; placement required on node-b.
				var forwarded models.CreateSandboxRequest
				raw, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(raw, &forwarded); err != nil || forwarded.Image != name || forwarded.ImageDistributionMode != "" {
					t.Fatalf("router sent image %q (mode %q, %v), a copy the target must pull; want the name %q pinned to the home",
						forwarded.Image, forwarded.ImageDistributionMode, err, name)
				}
				if got := r.Header.Get(HeaderTarget); got != "node-b" {
					t.Fatalf("%s = %q, want node-b", HeaderTarget, got)
				}
				if got := r.Header.Get(HeaderID); got != "" {
					t.Fatalf("%s = %q, want none", HeaderID, got)
				}
				if len(stub.selectReqs) != 1 || stub.selectReqs[0].RequiredNodeID != "node-b" {
					t.Fatalf("placement requests = %+v, want one pinned to node-b", stub.selectReqs)
				}
			}
			if len(stub.reserveCalls) != tc.wantReserve {
				t.Fatalf("ReserveOnTarget calls = %d, want %d", len(stub.reserveCalls), tc.wantReserve)
			}
			if !slices.Equal(stub.lookups, tc.wantLookups) {
				t.Fatalf("index lookups = %q, want %q", stub.lookups, tc.wantLookups)
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
		})
	}
}

// The pinned create reaches node-b, the snapshot's home. node-b serves it
// locally without asking the index (no second hop), boots the snapshot from
// its own image, and checks the owner as for a create sent there directly. A
// pinned create for a name node-b does not hold keeps today's 400.
func TestSnapshotNameCreatePinnedToHomeRunsThere(t *testing.T) {
	const name = "gym-start"
	members := []cluster.Member{
		{NodeID: "ingress-a", APIURL: "http://ingress-a", Alive: true, Role: config.NodeRoleIngress},
		{NodeID: "node-b", APIURL: "http://node-b", Alive: true, Role: config.NodeRoleWorker},
	}
	for _, tc := range []struct {
		name       string
		caller     string
		seed       bool
		wantStatus int
	}{
		{name: "owner_boots_its_snapshot_on_the_home", caller: "tenant-a", seed: true},
		{name: "name_not_held_here_is_refused", caller: "tenant-a", wantStatus: http.StatusBadRequest},
		{name: "other_tenant_is_refused", caller: "tenant-b", seed: true, wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := &snapshotHomeStub{
				clusterStub: &clusterStub{Noop: cluster.NewNoop("node-b", "http://node-b", ""), members: members},
				homes:       map[string]string{cluster.SnapshotLocalOnlyKey("tenant-a", name): "node-b"},
			}
			homeSvc, homeStore := newCreateService(t, home, true)
			var tag string
			if tc.seed {
				tag = seedCommittedSnapshot(t, homeStore, "tenant-a", name)
			}
			req := models.CreateSandboxRequest{Image: name}
			arrived := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil).WithContext(tenantCtx(tc.caller))
			arrived.Header.Set(HeaderTarget, "node-b")
			w := httptest.NewRecorder()
			decision, ok := Prepare(w, arrived, homeSvc, req, nil, PrepareOptions{})
			if len(home.lookups) != 0 || home.forwards != 0 {
				t.Fatalf("home looked up %v and forwarded %d times, want neither", home.lookups, home.forwards)
			}
			if tc.wantStatus != 0 {
				if ok || w.Code != tc.wantStatus {
					t.Fatalf("home ok=%v status=%d, want refused with %d", ok, w.Code, tc.wantStatus)
				}
				return
			}
			if !ok || decision.ReservationID != "" {
				t.Fatalf("home ok=%v reservation=%q (status %d %q), want a local create without reservation",
					ok, decision.ReservationID, w.Code, w.Body.String())
			}
			resp, err := CreateOnSelectedNode(arrived.Context(), homeSvc, nil, req, "", CreateOptions{})
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
