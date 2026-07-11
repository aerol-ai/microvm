package clustercreate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type clusterStub struct {
	*cluster.Noop
	owner      cluster.OwnerInfo
	ownerErr   error
	forwards   int
	lastTarget cluster.Endpoint
	deletes    int
	deleteErr  error
	cancels    int
	cancelErr  error

	selectTarget cluster.PlacementTarget
	selectErr    error
	selectReqs   []capacity.Request
	drained      bool
	members      []cluster.Member

	reserveErr   error
	reserveCalls []reserveCall

	recordErr   error
	recordPanic bool
	recordCalls []recordCall

	selfNodePanic bool
}

func (s *clusterStub) SelfNodeID() string {
	if s.selfNodePanic {
		panic("self node id panic")
	}
	return s.Noop.SelfNodeID()
}

type reserveCall struct {
	sandboxID string
	target    cluster.PlacementTarget
	redacted  *models.CreateSandboxRequest
	secrets   cluster.PlacementSecrets
	ttl       time.Duration
}

type recordCall struct {
	sandboxID string
	spec      *models.CreateSandboxRequest
	secrets   cluster.PlacementSecrets
}

func (s *clusterStub) OwnerOf(_ string) (cluster.OwnerInfo, error) {
	if s.ownerErr != nil {
		return cluster.OwnerInfo{}, s.ownerErr
	}
	return s.owner, nil
}

func (s *clusterStub) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, _ *http.Request) {
	s.forwards++
	s.lastTarget = target
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("forwarded"))
}

func (s *clusterStub) DeletePlacement(_ context.Context, _ string) error {
	s.deletes++
	return s.deleteErr
}

func (s *clusterStub) CancelReservation(_ context.Context, _ string) error {
	s.cancels++
	return s.cancelErr
}

func (s *clusterStub) SelectPlacement(req capacity.Request) (cluster.PlacementTarget, error) {
	s.selectReqs = append(s.selectReqs, req)
	if s.selectErr != nil {
		return cluster.PlacementTarget{}, s.selectErr
	}
	return s.selectTarget, nil
}

func (s *clusterStub) IsNodeDrained(_ string) bool {
	return s.drained
}

func (s *clusterStub) Members() []cluster.Member {
	if s.members != nil {
		return s.members
	}
	return s.Noop.Members()
}

func (s *clusterStub) ReserveOnTarget(_ context.Context, sandboxID string, target cluster.PlacementTarget, redacted *models.CreateSandboxRequest, secrets cluster.PlacementSecrets, ttl time.Duration) error {
	s.reserveCalls = append(s.reserveCalls, reserveCall{
		sandboxID: sandboxID,
		target:    target,
		redacted:  redacted,
		secrets:   secrets,
		ttl:       ttl,
	})
	return s.reserveErr
}

func (s *clusterStub) RecordPlacement(_ context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets cluster.PlacementSecrets) error {
	if s.recordPanic {
		panic("record placement panic")
	}
	s.recordCalls = append(s.recordCalls, recordCall{sandboxID: sandboxID, spec: spec, secrets: secrets})
	return s.recordErr
}

type fakeRuntime struct {
	mu          sync.Mutex
	states      map[string]*models.SandboxRuntimeState
	createDelay time.Duration
	createErr   error
	createPanic bool
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{states: map[string]*models.SandboxRuntimeState{}}
}

func (f *fakeRuntime) Create(_ context.Context, _ models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	if f.createDelay > 0 {
		time.Sleep(f.createDelay)
	}
	if f.createPanic {
		panic("create runtime panic")
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state := &models.SandboxRuntimeState{
		SandboxID:   sandboxID,
		ContainerID: "ctr-" + sandboxID,
		ContainerIP: "10.0.0.2",
		Status:      models.SandboxStatusStarted,
	}
	f.states[sandboxID] = cloneRuntimeState(state)
	return cloneRuntimeState(state), nil
}

func (f *fakeRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	return "", nil
}

func (f *fakeRuntime) Start(_ context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lookup(containerRef)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", containerRef)
	}
	state.Status = models.SandboxStatusStarted
	return cloneRuntimeState(state), nil
}

func (f *fakeRuntime) Stop(_ context.Context, containerRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lookup(containerRef)
	if !ok {
		return fmt.Errorf("sandbox %q not found", containerRef)
	}
	state.Status = models.SandboxStatusStopped
	return nil
}

func (f *fakeRuntime) Destroy(_ context.Context, sandbox *models.Sandbox) error {
	if sandbox == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.states, sandbox.ID)
	return nil
}

func (f *fakeRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	return nil
}

func (f *fakeRuntime) Inspect(_ context.Context, containerRef string) (*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.lookup(containerRef)
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", containerRef)
	}
	return cloneRuntimeState(state), nil
}

func (f *fakeRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]*models.SandboxRuntimeState, len(f.states))
	for id, state := range f.states {
		out[id] = cloneRuntimeState(state)
	}
	return out, nil
}

func (f *fakeRuntime) Ping(context.Context) error { return nil }
func (f *fakeRuntime) RemoveImage(context.Context, string) error {
	return nil
}
func (f *fakeRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	return nil
}
func (f *fakeRuntime) ClearNetworkRules(string) error                     { return nil }
func (f *fakeRuntime) ApplyEgressPolicy(string, []string, []string) error { return nil }
func (f *fakeRuntime) ClearEgressPolicy(string, []string, []string) error { return nil }
func (f *fakeRuntime) ApplyNetworkBlockAll(string) error                  { return nil }
func (f *fakeRuntime) ApplyNetworkBlockIngress(string) error              { return nil }
func (f *fakeRuntime) ClearNetworkBlockIngress(string) error              { return nil }
func (f *fakeRuntime) ClearNetworkBlockEgress(string) error               { return nil }

func (f *fakeRuntime) lookup(containerRef string) (*models.SandboxRuntimeState, bool) {
	if state, ok := f.states[containerRef]; ok {
		return state, true
	}
	for _, state := range f.states {
		if state.ContainerID == containerRef {
			return state, true
		}
	}
	return nil, false
}

func cloneRuntimeState(state *models.SandboxRuntimeState) *models.SandboxRuntimeState {
	if state == nil {
		return nil
	}
	cloned := *state
	return &cloned
}

func testServiceWithCluster(c cluster.Client) *service.Service {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	return svc
}

func newCreateService(t *testing.T, c cluster.Client, withCipher bool) (*service.Service, *store.Store) {
	t.Helper()
	return newCreateServiceWithRuntime(t, c, newFakeRuntime(), withCipher)
}

func newCreateServiceWithRuntime(t *testing.T, c cluster.Client, rt *fakeRuntime, withCipher bool) (*service.Service, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     filepath.Join(dir, "mounts"),
		CredDir:     filepath.Join(dir, "creds"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	var cipher *secrets.Cipher
	if withCipher {
		cipher, err = secrets.NewCipher("", filepath.Join(dir, "cipher.key"))
		if err != nil {
			t.Fatalf("secrets.NewCipher: %v", err)
		}
	}

	cfg := config.Config{EnableCaddy: false, ToolboxPort: 2280}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(cfg, logger, st, rt, nil, caddy.New(cfg), cipher, mgr, nil)
	if c != nil {
		svc.AttachCluster(c)
	}
	return svc, st
}

func TestCapacityRequestFromCreate_DefaultsAndGPU(t *testing.T) {
	got := CapacityRequestFromCreate(models.CreateSandboxRequest{
		Runtime: models.RuntimeFirecracker,
		GPUs: &models.GPURequest{
			Vendor: models.GPUVendorNVIDIA,
			Count:  0,
		},
	})
	if got.CPU != models.DefaultCPU || got.MemoryMB != models.DefaultMemoryMB || got.DiskGB != models.DefaultDiskGB {
		t.Fatalf("defaults not applied: %+v", got)
	}
	if got.GPUs != 1 || got.GPUVendor != string(models.GPUVendorNVIDIA) {
		t.Fatalf("gpu fields mismatch: %+v", got)
	}
	if got.Runtime != models.RuntimeFirecracker {
		t.Fatalf("runtime mismatch: %q", got.Runtime)
	}
}

func TestRouteExistingPlacement(t *testing.T) {
	tests := []struct {
		name        string
		stub        *clusterStub
		wantHandled bool
		wantLocal   bool
		wantCode    int
		wantForward bool
	}{
		{
			name:        "owner_lookup_error_is_unhandled",
			stub:        &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), ownerErr: errors.New("boom")},
			wantHandled: false,
			wantLocal:   false,
		},
		{
			name:        "self_owner_returns_local",
			stub:        &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), owner: cluster.OwnerInfo{NodeID: "node-a", IsSelf: true}},
			wantHandled: false,
			wantLocal:   true,
		},
		{
			name:        "remote_owner_without_urls_is_handled_error",
			stub:        &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), owner: cluster.OwnerInfo{NodeID: "node-b"}},
			wantHandled: true,
			wantLocal:   false,
			wantCode:    http.StatusServiceUnavailable,
		},
		{
			name:        "remote_owner_forwards",
			stub:        &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), owner: cluster.OwnerInfo{NodeID: "node-b", APIURL: "https://node-b.example", InternalURL: "https://node-b.internal"}},
			wantHandled: true,
			wantLocal:   false,
			wantForward: true,
			wantCode:    http.StatusAccepted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
			w := httptest.NewRecorder()
			var status int
			var message string

			handled, local := routeExistingPlacement(w, r, tc.stub, "sb-1", func(_ http.ResponseWriter, code int, msg string) {
				status = code
				message = msg
				w.WriteHeader(code)
			})

			if handled != tc.wantHandled || local != tc.wantLocal {
				t.Fatalf("(handled,local) = (%v,%v), want (%v,%v)", handled, local, tc.wantHandled, tc.wantLocal)
			}
			if tc.stub.ownerErr == nil {
				if got := r.Header.Get(HeaderID); got != "sb-1" {
					t.Fatalf("%s = %q, want sb-1", HeaderID, got)
				}
				if got := r.Header.Get(HeaderTarget); tc.stub.owner.NodeID != "" && got != tc.stub.owner.NodeID {
					t.Fatalf("%s = %q, want %q", HeaderTarget, got, tc.stub.owner.NodeID)
				}
			}
			if tc.wantForward {
				if tc.stub.forwards != 1 {
					t.Fatalf("ForwardHTTP calls = %d, want 1", tc.stub.forwards)
				}
				if tc.stub.lastTarget.APIURL != tc.stub.owner.APIURL || tc.stub.lastTarget.InternalURL != tc.stub.owner.InternalURL {
					t.Fatalf("forward target mismatch: %+v", tc.stub.lastTarget)
				}
			}
			if tc.wantCode != 0 {
				if w.Code != tc.wantCode {
					t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
				}
				if tc.wantCode == http.StatusServiceUnavailable && !strings.Contains(message, "URL unknown") {
					t.Fatalf("message = %q, want URL unknown", message)
				}
			}
			if tc.wantCode == 0 && status != 0 {
				t.Fatalf("unexpected error status: %d", status)
			}
		})
	}
}

func TestPrepare_ForwardedHeaderValidation(t *testing.T) {
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "https://node-a.example", "")}
	svc := testServiceWithCluster(stub)
	baseReq := models.CreateSandboxRequest{Image: "alpine:3.20"}

	t.Run("wrong_target_rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set(HeaderTarget, "node-b")
		w := httptest.NewRecorder()
		var status int
		_, ok := Prepare(w, r, svc, baseReq, func(_ http.ResponseWriter, code int, _ string) {
			status = code
		}, PrepareOptions{})
		if ok {
			t.Fatal("Prepare returned ok=true, want false")
		}
		if status != http.StatusMisdirectedRequest {
			t.Fatalf("status = %d, want %d", status, http.StatusMisdirectedRequest)
		}
	})

	t.Run("forwarded_missing_id_rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set(HeaderTarget, "node-a")
		w := httptest.NewRecorder()
		var status int
		_, ok := Prepare(w, r, svc, baseReq, func(_ http.ResponseWriter, code int, _ string) {
			status = code
		}, PrepareOptions{})
		if ok {
			t.Fatal("Prepare returned ok=true, want false")
		}
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", status, http.StatusBadRequest)
		}
	})

	t.Run("forwarded_self_with_id_accepted", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set(HeaderTarget, "node-a")
		r.Header.Set(HeaderID, "sb-fixed")
		w := httptest.NewRecorder()
		decision, ok := Prepare(w, r, svc, baseReq, nil, PrepareOptions{})
		if !ok {
			t.Fatal("Prepare returned ok=false, want true")
		}
		if decision.ReservationID != "sb-fixed" {
			t.Fatalf("ReservationID = %q, want sb-fixed", decision.ReservationID)
		}
	})
}

func TestPrepare_GuardsAndPlacementBranches(t *testing.T) {
	baseReq := models.CreateSandboxRequest{Image: "alpine:3.20"}
	r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	w := httptest.NewRecorder()

	if _, ok := Prepare(w, r, nil, baseReq, nil, PrepareOptions{}); !ok {
		t.Fatal("nil service should fall through locally")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svcNoCluster := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	if _, ok := Prepare(w, r, svcNoCluster, baseReq, nil, PrepareOptions{}); !ok {
		t.Fatal("service without cluster should fall through locally")
	}

	t.Run("local_only_image_rejected_when_drained", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), drained: true}
		svc := testServiceWithCluster(stub)
		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image:                 "e2b/sb-local:default",
			ImageDistributionMode: models.ImageDistributionLocalOnly,
		}, func(_ http.ResponseWriter, code int, _ string) {
			status = code
		}, PrepareOptions{})
		if ok {
			t.Fatal("Prepare returned ok=true, want false")
		}
		if status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", status, http.StatusServiceUnavailable)
		}
		if len(stub.selectReqs) != 0 {
			t.Fatalf("SelectPlacement calls = %d, want 0", len(stub.selectReqs))
		}
	})

	t.Run("local_only_image_stays_local", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
		svc := testServiceWithCluster(stub)
		decision, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image:                 "e2b/sb-local:default",
			ImageDistributionMode: models.ImageDistributionLocalOnly,
		}, nil, PrepareOptions{})
		if !ok {
			t.Fatal("Prepare returned ok=false, want true")
		}
		if decision.ReservationID != "" {
			t.Fatalf("ReservationID = %q, want empty", decision.ReservationID)
		}
	})

	t.Run("local_only_image_routes_from_non_worker", func(t *testing.T) {
		stub := &clusterStub{
			Noop:         cluster.NewNoop("server-a", "http://server-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b", IsSelf: false},
			members: []cluster.Member{
				{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
				{NodeID: "worker-b", APIURL: "http://worker-b", Alive: true, Role: config.NodeRoleWorker},
			},
		}
		svc := testServiceWithCluster(stub)
		decision, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, nil, PrepareOptions{})
		if ok {
			t.Fatal("Prepare returned ok=true, want false after forwarding")
		}
		if decision.ReservationID != "" {
			t.Fatalf("ReservationID = %q, want empty", decision.ReservationID)
		}
		if stub.forwards != 1 {
			t.Fatalf("ForwardHTTP calls = %d, want 1", stub.forwards)
		}
		if len(stub.reserveCalls) != 0 {
			t.Fatalf("ReserveOnTarget calls = %d, want 0 for local-only image", len(stub.reserveCalls))
		}
		if len(stub.selectReqs) != 1 || stub.selectReqs[0].Runtime != models.RuntimeDocker {
			t.Fatalf("placement request = %+v, want docker runtime", stub.selectReqs)
		}
	})

	t.Run("select_placement_error_shapes", func(t *testing.T) {
		tests := []struct {
			name           string
			err            error
			wantStatus     int
			wantRetryAfter string
		}{
			{name: "no_target", err: cluster.ErrNoPlacementTarget, wantStatus: http.StatusServiceUnavailable, wantRetryAfter: "30"},
			{name: "invalid_topology", err: cluster.ErrInvalidTopology, wantStatus: http.StatusServiceUnavailable, wantRetryAfter: "300"},
			{name: "generic", err: errors.New("boom"), wantStatus: http.StatusInternalServerError},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), selectErr: tc.err}
				svc := testServiceWithCluster(stub)
				w := httptest.NewRecorder()
				var status int
				_, ok := Prepare(w, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, baseReq, func(_ http.ResponseWriter, code int, _ string) {
					status = code
				}, PrepareOptions{})
				if ok {
					t.Fatal("Prepare returned ok=true, want false")
				}
				if status != tc.wantStatus {
					t.Fatalf("status = %d, want %d", status, tc.wantStatus)
				}
				if got := w.Header().Get("Retry-After"); got != tc.wantRetryAfter {
					t.Fatalf("Retry-After = %q, want %q", got, tc.wantRetryAfter)
				}
			})
		}
	})
}

func TestCapacityRequestFromCreateIncludesModuleAndBuiltImageRuntime(t *testing.T) {
	def := CapacityRequestFromCreate(models.CreateSandboxRequest{})
	if def.Runtime != models.RuntimeDocker {
		t.Fatalf("default runtime = %q, want docker", def.Runtime)
	}

	wasm := CapacityRequestFromCreate(models.CreateSandboxRequest{
		Runtime:   models.RuntimeWasm,
		ModuleRef: "python",
		MemoryMB:  128,
	})
	if wasm.ModuleRef != "python" || wasm.MemoryMB != 136 {
		t.Fatalf("wasm capacity request = %+v, want module ref and overhead", wasm)
	}

	built := CapacityRequestFromCreate(models.CreateSandboxRequest{Image: docker.BuiltImageNamespace + "/abc:latest"})
	if built.Runtime != models.RuntimeDocker {
		t.Fatalf("built image runtime = %q, want docker", built.Runtime)
	}
}

func TestDiskGBForCapacityClustercreate(t *testing.T) {
	if got := diskGBForCapacity(10, models.RuntimeDocker, 5); got != 10 {
		t.Fatalf("docker disk = %d, want 10", got)
	}
	if got := diskGBForCapacity(10, models.RuntimeFirecracker, 5); got != 15 {
		t.Fatalf("firecracker overlay disk = %d, want 15", got)
	}
}

func TestClusterCreateSelfCanOwnSandboxClustercreate(t *testing.T) {
	if !clusterCreateSelfCanOwnSandbox(nil) {
		t.Fatal("nil cluster should default true")
	}
	stub := &clusterStub{
		Noop: cluster.NewNoop("server-a", "", ""),
		members: []cluster.Member{
			{NodeID: "server-a", Role: config.NodeRoleServer},
		},
	}
	if clusterCreateSelfCanOwnSandbox(stub) {
		t.Fatal("server should not own sandboxes")
	}
}

func TestPrepareLocalImageCoverageBranches(t *testing.T) {
	t.Run("forwarded_local_image_without_reservation", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("worker-b", "http://worker-b", "")}
		svc := testServiceWithCluster(stub)
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set(HeaderTarget, "worker-b")
		decision, ok := Prepare(httptest.NewRecorder(), r, svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, nil, PrepareOptions{})
		if !ok || decision.ReservationID != "" {
			t.Fatalf("ok=%v reservation=%q, want local forward accept", ok, decision.ReservationID)
		}
	})

	t.Run("non_worker_placement_self_drained", func(t *testing.T) {
		stub := &clusterStub{
			Noop:         cluster.NewNoop("server-a", "http://server-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "server-a", IsSelf: true},
			members: []cluster.Member{
				{NodeID: "server-a", Role: config.NodeRoleServer},
			},
			drained: true,
		}
		svc := testServiceWithCluster(stub)
		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusServiceUnavailable {
			t.Fatalf("ok=%v status=%d, want 503", ok, status)
		}
	})

	t.Run("non_worker_placement_empty_urls", func(t *testing.T) {
		stub := &clusterStub{
			Noop:         cluster.NewNoop("server-a", "http://server-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "worker-b", IsSelf: false},
			members: []cluster.Member{
				{NodeID: "server-a", Role: config.NodeRoleServer},
				{NodeID: "worker-b", Role: config.NodeRoleWorker},
			},
		}
		svc := testServiceWithCluster(stub)
		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusServiceUnavailable {
			t.Fatalf("ok=%v status=%d, want 503", ok, status)
		}
	})

	t.Run("non_worker_placement_generic_error", func(t *testing.T) {
		stub := &clusterStub{
			Noop:      cluster.NewNoop("server-a", "http://server-a", ""),
			selectErr: errors.New("boom"),
			members: []cluster.Member{
				{NodeID: "server-a", Role: config.NodeRoleServer},
			},
		}
		svc := testServiceWithCluster(stub)
		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{
			Image: docker.BuiltImageNamespace + "/abc:latest",
		}, func(_ http.ResponseWriter, code int, _ string) { status = code }, PrepareOptions{})
		if ok || status != http.StatusInternalServerError {
			t.Fatalf("ok=%v status=%d, want 500", ok, status)
		}
	})

	t.Run("non_worker_server_role_in_members", func(t *testing.T) {
		stub := &clusterStub{
			Noop: cluster.NewNoop("server-a", "http://server-a", ""),
			members: []cluster.Member{
				{NodeID: "server-a", Role: config.NodeRoleServer},
			},
		}
		svc := testServiceWithCluster(stub)
		if clusterCreateSelfCanOwnSandbox(stub) {
			t.Fatal("expected server role to block self ownership")
		}
		_ = svc
	})
}

func TestPrepare_ReservePaths(t *testing.T) {
	baseReq := models.CreateSandboxRequest{
		Image: "private.example.com/app:latest",
		Registry: &models.RegistryAuth{
			Server:   "private.example.com",
			Username: "u",
			Password: "super-secret",
		},
	}

	t.Run("reserve_self_sets_headers_and_returns_decision", func(t *testing.T) {
		stub := &clusterStub{
			Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
		}
		svc := testServiceWithCluster(stub)
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		w := httptest.NewRecorder()
		decision, ok := Prepare(w, r, svc, baseReq, nil, PrepareOptions{PreferredSandboxID: "sb-preferred"})
		if !ok {
			t.Fatal("Prepare returned ok=false, want true")
		}
		if decision.ReservationID != "sb-preferred" {
			t.Fatalf("ReservationID = %q, want sb-preferred", decision.ReservationID)
		}
		if got := r.Header.Get(HeaderTarget); got != "node-a" {
			t.Fatalf("%s = %q, want node-a", HeaderTarget, got)
		}
		if got := r.Header.Get(HeaderID); got != "sb-preferred" {
			t.Fatalf("%s = %q, want sb-preferred", HeaderID, got)
		}
		if len(stub.reserveCalls) != 1 {
			t.Fatalf("ReserveOnTarget calls = %d, want 1", len(stub.reserveCalls))
		}
		rc := stub.reserveCalls[0]
		if rc.ttl != ReservationTTL {
			t.Fatalf("ttl = %v, want %v", rc.ttl, ReservationTTL)
		}
		if rc.redacted == nil || rc.redacted.Registry == nil || rc.redacted.Registry.Password != "" {
			t.Fatalf("redacted registry = %+v, want password stripped", rc.redacted.Registry)
		}
		if rc.secrets.Ref != "" || rc.secrets.Version != 0 || len(rc.secrets.LegacySealed) != 0 {
			t.Fatalf("reservation secrets = %+v, want empty", rc.secrets)
		}
	})

	t.Run("reserve_remote_forwards", func(t *testing.T) {
		stub := &clusterStub{
			Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b", InternalURL: "http://node-b.internal"},
		}
		svc := testServiceWithCluster(stub)
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		w := httptest.NewRecorder()
		decision, ok := Prepare(w, r, svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{PreferredSandboxID: "sb-remote"})
		if ok {
			t.Fatal("Prepare returned ok=true, want false after forwarding")
		}
		if decision.ReservationID != "" {
			t.Fatalf("ReservationID = %q, want empty", decision.ReservationID)
		}
		if stub.forwards != 1 {
			t.Fatalf("ForwardHTTP calls = %d, want 1", stub.forwards)
		}
		if stub.lastTarget.InternalURL != "http://node-b.internal" {
			t.Fatalf("forward target = %+v", stub.lastTarget)
		}
		if w.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusAccepted)
		}
	})

	t.Run("reserve_error_shapes", func(t *testing.T) {
		tests := []struct {
			name           string
			err            error
			opts           PrepareOptions
			owner          cluster.OwnerInfo
			wantStatus     int
			wantRetryAfter string
			wantOK         bool
			wantDecisionID string
			wantForwards   int
		}{
			{
				name:           "preferred_id_conflict_local_owner_reuses_reservation",
				err:            cluster.ErrReservationConflict,
				opts:           PrepareOptions{PreferredSandboxID: "sb-fixed"},
				owner:          cluster.OwnerInfo{NodeID: "node-a", IsSelf: true},
				wantOK:         true,
				wantDecisionID: "sb-fixed",
			},
			{
				name:         "preferred_id_conflict_remote_owner_forwards",
				err:          cluster.ErrReservationConflict,
				opts:         PrepareOptions{PreferredSandboxID: "sb-fixed"},
				owner:        cluster.OwnerInfo{NodeID: "node-b", APIURL: "http://node-b"},
				wantStatus:   http.StatusAccepted,
				wantForwards: 1,
			},
			{
				name:       "preferred_id_conflict_owner_without_url_returns_503",
				err:        cluster.ErrReservationConflict,
				opts:       PrepareOptions{PreferredSandboxID: "sb-fixed"},
				owner:      cluster.OwnerInfo{NodeID: "node-b"},
				wantStatus: http.StatusServiceUnavailable,
			},
			{name: "name_conflict", err: cluster.ErrNameConflict, wantStatus: http.StatusConflict},
			{name: "reservation_conflict", err: cluster.ErrReservationConflict, wantStatus: http.StatusConflict},
			{name: "backpressure", err: cluster.ErrCreateBackpressure, wantStatus: http.StatusTooManyRequests, wantRetryAfter: "5"},
			{name: "capacity_exceeded", err: cluster.ErrCapacityExceeded, wantStatus: http.StatusServiceUnavailable, wantRetryAfter: "30"},
			{name: "no_target_after_reserve", err: cluster.ErrNoPlacementTarget, wantStatus: http.StatusServiceUnavailable, wantRetryAfter: "30"},
			{name: "generic", err: errors.New("raft commit timed out"), wantStatus: http.StatusServiceUnavailable},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				stub := &clusterStub{
					Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
					selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
					reserveErr:   tc.err,
					owner:        tc.owner,
				}
				svc := testServiceWithCluster(stub)
				w := httptest.NewRecorder()
				var status int
				decision, ok := Prepare(w, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, func(_ http.ResponseWriter, code int, _ string) {
					status = code
				}, tc.opts)
				if ok != tc.wantOK {
					t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
				}
				if decision.ReservationID != tc.wantDecisionID {
					t.Fatalf("ReservationID = %q, want %q", decision.ReservationID, tc.wantDecisionID)
				}
				if tc.wantStatus != 0 {
					gotStatus := status
					if w.Code != 200 {
						gotStatus = w.Code
					}
					if gotStatus != tc.wantStatus {
						t.Fatalf("status = %d, want %d", gotStatus, tc.wantStatus)
					}
				}
				if got := w.Header().Get("Retry-After"); got != tc.wantRetryAfter {
					t.Fatalf("Retry-After = %q, want %q", got, tc.wantRetryAfter)
				}
				if stub.forwards != tc.wantForwards {
					t.Fatalf("ForwardHTTP calls = %d, want %d", stub.forwards, tc.wantForwards)
				}
			})
		}
	})
}

func TestCreateOnSelectedNode(t *testing.T) {
	t.Run("create_with_reservation_promotes_without_spec", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		svc, st := newCreateService(t, stub, false)
		resp, err := CreateOnSelectedNode(context.Background(), svc, nil, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-fixed", CreateOptions{})
		if err != nil {
			t.Fatalf("CreateOnSelectedNode: %v", err)
		}
		if resp.Sandbox.ID != "sb-fixed" {
			t.Fatalf("sandbox id = %q, want sb-fixed", resp.Sandbox.ID)
		}
		if len(stub.recordCalls) != 1 {
			t.Fatalf("RecordPlacement calls = %d, want 1", len(stub.recordCalls))
		}
		if stub.recordCalls[0].spec != nil {
			t.Fatalf("recorded spec = %+v, want nil when PromoteWithSpec is false", stub.recordCalls[0].spec)
		}
		if _, err := st.Get(context.Background(), "sb-fixed"); err != nil {
			t.Fatalf("store.Get(sb-fixed): %v", err)
		}
	})

	t.Run("create_with_reservation_promotes_with_redacted_spec", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		svc, _ := newCreateService(t, stub, true)
		req := models.CreateSandboxRequest{
			Image: "private.example.com/app:latest",
			Registry: &models.RegistryAuth{
				Server:   "private.example.com",
				Username: "u",
				Password: "secret",
			},
		}
		resp, err := CreateOnSelectedNode(context.Background(), svc, nil, req, "sb-secret", CreateOptions{PromoteWithSpec: true})
		if err != nil {
			t.Fatalf("CreateOnSelectedNode: %v", err)
		}
		if resp.Sandbox.ID != "sb-secret" {
			t.Fatalf("sandbox id = %q, want sb-secret", resp.Sandbox.ID)
		}
		if len(stub.recordCalls) != 1 {
			t.Fatalf("RecordPlacement calls = %d, want 1", len(stub.recordCalls))
		}
		rc := stub.recordCalls[0]
		if rc.spec == nil || rc.spec.Registry == nil || rc.spec.Registry.Password != "" {
			t.Fatalf("recorded redacted registry = %+v", rc.spec)
		}
		if rc.secrets.Ref == "" || rc.secrets.Version == 0 {
			t.Fatalf("recorded secrets = %+v, want provider ref", rc.secrets)
		}
	})

	t.Run("create_without_reservation_uses_create_sandbox", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		svc, _ := newCreateService(t, stub, false)
		resp, err := CreateOnSelectedNode(context.Background(), svc, nil, models.CreateSandboxRequest{Image: "alpine:3.20"}, "", CreateOptions{})
		if err != nil {
			t.Fatalf("CreateOnSelectedNode: %v", err)
		}
		if resp.Sandbox.ID == "" {
			t.Fatal("sandbox id empty")
		}
		if len(stub.recordCalls) != 1 {
			t.Fatalf("RecordPlacement calls = %d, want 1", len(stub.recordCalls))
		}
	})

	t.Run("create_failure_cancels_reservation", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		svc, _ := newCreateService(t, stub, false)
		_, err := CreateOnSelectedNode(context.Background(), svc, nil, models.CreateSandboxRequest{}, "sb-bad", CreateOptions{})
		if err == nil {
			t.Fatal("CreateOnSelectedNode unexpectedly succeeded")
		}
		// Overlap may promote before create fails; retract DeletePlacement.
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
		}
		if stub.cancels != 1 {
			t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
		}
	})

	t.Run("promote_ok_create_fail_retracts_placement", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		rt := &fakeRuntime{
			states:      map[string]*models.SandboxRuntimeState{},
			createDelay: 40 * time.Millisecond,
			createErr:   errors.New("boom"),
		}
		svc, st := newCreateServiceWithRuntime(t, stub, rt, false)
		_, err := CreateOnSelectedNode(context.Background(), svc, nil, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-overlap-fail", CreateOptions{})
		if err == nil {
			t.Fatal("CreateOnSelectedNode unexpectedly succeeded")
		}
		if len(stub.recordCalls) != 1 {
			t.Fatalf("RecordPlacement calls = %d, want 1 (promote-OK before create-FAIL)", len(stub.recordCalls))
		}
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
		}
		if _, getErr := st.Get(context.Background(), "sb-overlap-fail"); !errors.Is(getErr, store.ErrNotFound) {
			t.Fatalf("store row after retract = %v, want ErrNotFound", getErr)
		}
	})

	t.Run("delete_placement_error_still_surfaces_create_error", func(t *testing.T) {
		stub := &clusterStub{
			Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
			deleteErr: errors.New("raft delete failed"),
		}
		rt := &fakeRuntime{
			states:      map[string]*models.SandboxRuntimeState{},
			createDelay: 40 * time.Millisecond,
			createErr:   errors.New("create boom"),
		}
		svc, _ := newCreateServiceWithRuntime(t, stub, rt, false)
		_, err := CreateOnSelectedNode(context.Background(), svc, nil, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-retract-fail", CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "create boom") {
			t.Fatalf("error = %v, want original create error", err)
		}
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1 (attempted)", stub.deletes)
		}
	})

	t.Run("record_placement_failure_rolls_back", func(t *testing.T) {
		stub := &clusterStub{
			Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
			recordErr: errors.New("raft write failed"),
		}
		svc, st := newCreateService(t, stub, false)
		_, err := CreateOnSelectedNode(context.Background(), svc, nil, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-rollback", CreateOptions{})
		if err == nil || !strings.Contains(err.Error(), "raft write failed") {
			t.Fatalf("error = %v, want record placement failure", err)
		}
		if stub.cancels != 1 {
			t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
		}
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
		}
		if _, err := st.Get(context.Background(), "sb-rollback"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("store.Get(sb-rollback) err = %v, want ErrNotFound after rollback", err)
		}
	})
}

func TestRollbackAndBestEffortHelpers(t *testing.T) {
	t.Run("rollback_destroy_delete_and_cancel", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
		svc, st := newCreateService(t, stub, false)
		if _, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-to-rollback"); err != nil {
			t.Fatalf("CreateSandboxWithID: %v", err)
		}
		rollbackCreate(context.Background(), svc, stub, nil, "sb-to-rollback", "sb-to-rollback")
		if stub.cancels != 1 {
			t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
		}
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
		}
		if _, err := st.Get(context.Background(), "sb-to-rollback"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("store.Get(sb-to-rollback) err = %v, want ErrNotFound", err)
		}
	})

	t.Run("delete_and_cancel_reservation_best_effort", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
		svc := testServiceWithCluster(stub)

		DeletePlacementBestEffort(context.Background(), svc, nil, "sb-1")
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
		}
		CancelReservationBestEffort(context.Background(), svc, nil, "sb-1")
		if stub.cancels != 1 {
			t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
		}

		DeletePlacementBestEffort(context.Background(), nil, nil, "sb-1")
		DeletePlacementBestEffort(context.Background(), svc, nil, "")
		CancelReservationBestEffort(context.Background(), nil, nil, "sb-1")
		CancelReservationBestEffort(context.Background(), svc, nil, "")

		if stub.deletes != 1 || stub.cancels != 1 {
			t.Fatalf("guard calls changed counts: deletes=%d cancels=%d", stub.deletes, stub.cancels)
		}
	})

	t.Run("best_effort_helpers_ignore_nil_cluster_and_loggable_errors", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		svcNoCluster := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		DeletePlacementBestEffort(context.Background(), svcNoCluster, logger, "sb-nocluster")
		CancelReservationBestEffort(context.Background(), svcNoCluster, logger, "sb-nocluster")

		stub := &clusterStub{
			Noop:      cluster.NewNoop("node-a", "", ""),
			deleteErr: errors.New("delete failed"),
			cancelErr: errors.New("cancel failed"),
		}
		DeletePlacementBestEffort(context.Background(), testServiceWithCluster(stub), logger, "sb-log")
		cancelReservation(context.Background(), stub, logger, "sb-log")
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
		}
		if stub.cancels != 1 {
			t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
		}
	})

	t.Run("rollback_handles_destroy_failure_without_cluster", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		svc, _ := newCreateService(t, nil, false)
		rollbackCreate(context.Background(), svc, nil, logger, "missing-sandbox", "")
	})
}

func TestOverlapCreateAndPromote_Guards(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("empty_reservation_id", func(t *testing.T) {
		svc, _ := newCreateService(t, nil, false)
		if _, err := OverlapCreateAndPromote(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "  ", OverlapOptions{}); err == nil || !strings.Contains(err.Error(), "requires reservationID") {
			t.Fatalf("error = %v, want reservationID guard", err)
		}
	})

	t.Run("nil_service", func(t *testing.T) {
		if _, err := OverlapCreateAndPromote(context.Background(), nil, logger, models.CreateSandboxRequest{}, "sb-x", OverlapOptions{}); err == nil || !strings.Contains(err.Error(), "service is nil") {
			t.Fatalf("error = %v, want nil-service guard", err)
		}
	})

	t.Run("no_cluster_falls_back_sequential", func(t *testing.T) {
		svc, st := newCreateService(t, nil, false)
		resp, err := OverlapCreateAndPromote(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-seq", OverlapOptions{})
		if err != nil {
			t.Fatalf("OverlapCreateAndPromote: %v", err)
		}
		if resp.Sandbox.ID != "sb-seq" {
			t.Fatalf("sandbox id = %q, want sb-seq", resp.Sandbox.ID)
		}
		if _, err := st.Get(context.Background(), "sb-seq"); err != nil {
			t.Fatalf("store.Get(sb-seq): %v", err)
		}
	})
}

// A panic in either leg must degrade to a leg failure (join + retract), not
// crash the daemon — bare goroutines are outside net/http's per-request
// recover, so an unrecovered panic here would take down every sandbox on the
// node.
func TestOverlapCreateAndPromote_PanicRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("create_leg_panic_retracts", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		rt := newFakeRuntime()
		rt.createPanic = true
		svc, _ := newCreateServiceWithRuntime(t, stub, rt, false)
		_, err := OverlapCreateAndPromote(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-panic-create", OverlapOptions{})
		of, ok := AsOverlapFailure(err)
		if !ok || of.Phase != OverlapPhaseCreate || !strings.Contains(of.Error(), "panicked") {
			t.Fatalf("error = %v, want create-phase panic failure", err)
		}
		if stub.deletes != 1 || stub.cancels != 1 {
			t.Fatalf("retract calls delete=%d cancel=%d, want 1/1", stub.deletes, stub.cancels)
		}
	})

	t.Run("promote_leg_panic_retracts", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		stub.recordPanic = true
		svc, st := newCreateService(t, stub, false)
		_, err := OverlapCreateAndPromote(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-panic-promote", OverlapOptions{})
		of, ok := AsOverlapFailure(err)
		if !ok || of.Phase != OverlapPhasePromote || !strings.Contains(of.Error(), "panicked") {
			t.Fatalf("error = %v, want promote-phase panic failure", err)
		}
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
		}
		if _, getErr := st.Get(context.Background(), "sb-panic-promote"); !errors.Is(getErr, store.ErrNotFound) {
			t.Fatalf("store row after retract = %v, want ErrNotFound", getErr)
		}
	})
}

func TestOverlapCreateAndPromote_SealFailRetracts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("seal_stage_panic_maps_to_seal_phase", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		stub.selfNodePanic = true // fires inside the promote leg, at seal stage
		svc, st := newCreateService(t, stub, false)
		_, err := OverlapCreateAndPromote(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-seal-panic", OverlapOptions{PromoteWithSpec: true})
		of, ok := AsOverlapFailure(err)
		if !ok || of.Phase != OverlapPhaseSeal || !strings.Contains(of.Error(), "panicked") {
			t.Fatalf("error = %v, want seal-phase panic failure", err)
		}
		if len(stub.recordCalls) != 0 {
			t.Fatalf("RecordPlacement calls = %d, want 0 after seal failure", len(stub.recordCalls))
		}
		if stub.deletes != 1 || stub.cancels != 1 {
			t.Fatalf("retract calls delete=%d cancel=%d, want 1/1", stub.deletes, stub.cancels)
		}
		if _, getErr := st.Get(context.Background(), "sb-seal-panic"); !errors.Is(getErr, store.ErrNotFound) {
			t.Fatalf("store row after retract = %v, want ErrNotFound", getErr)
		}
	})

	t.Run("create_error_takes_precedence_when_both_legs_fail", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		// No cipher + registry password: BOTH legs fail on "cipher not
		// initialized" — the surfaced phase must be create (switch order).
		svc, _ := newCreateService(t, stub, false)
		req := models.CreateSandboxRequest{
			Image:    "private.example.com/app:latest",
			Registry: &models.RegistryAuth{Server: "private.example.com", Username: "u", Password: "secret"},
		}
		_, err := OverlapCreateAndPromote(context.Background(), svc, logger, req, "sb-both-fail", OverlapOptions{PromoteWithSpec: true})
		of, ok := AsOverlapFailure(err)
		if !ok || of.Phase != OverlapPhaseCreate {
			t.Fatalf("error = %v, want create-phase precedence", err)
		}
		if stub.deletes != 1 || stub.cancels != 1 {
			t.Fatalf("retract calls delete=%d cancel=%d, want 1/1", stub.deletes, stub.cancels)
		}
	})
}

func TestRetractAfterOverlap_ErrorBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("all_steps_fail_after_promote", func(t *testing.T) {
		stub := &clusterStub{
			Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
			deleteErr: errors.New("raft delete failed"),
		}
		svc, st := newCreateService(t, stub, false)
		_ = st.Close() // secrets + destroy both hit the closed store
		retractAfterOverlap(context.Background(), svc, stub, logger, "sb-retract-err",
			createLegResult{}, promoteLegResult{promoteErr: errors.New("promote boom")})
		if stub.deletes != 1 || stub.cancels != 1 {
			t.Fatalf("retract calls delete=%d cancel=%d, want 1/1", stub.deletes, stub.cancels)
		}
	})

	t.Run("destroy_quiet_after_create_failure", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
		svc, st := newCreateService(t, stub, false)
		_ = st.Close()
		retractAfterOverlap(context.Background(), svc, stub, logger, "sb-retract-quiet",
			createLegResult{err: errors.New("create boom")}, promoteLegResult{})
		if stub.deletes != 1 {
			t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
		}
	})

	t.Run("nil_cluster_skips_placement_ops", func(t *testing.T) {
		svc, _ := newCreateService(t, nil, false)
		retractAfterOverlap(context.Background(), svc, nil, logger, "sb-no-cluster",
			createLegResult{err: errors.New("create boom")}, promoteLegResult{})
	})
}

func TestOverlapFailureHelpers(t *testing.T) {
	base := errors.New("boom")
	f := &OverlapFailure{Phase: OverlapPhasePromote, Err: base}
	if f.Error() != "boom" || !errors.Is(f, base) {
		t.Fatalf("Error/Unwrap: %q, Is=%v", f.Error(), errors.Is(f, base))
	}
	var nilF *OverlapFailure
	if nilF.Error() != "clustercreate: overlap failure" || nilF.Unwrap() != nil {
		t.Fatalf("nil receiver: Error=%q Unwrap=%v", nilF.Error(), nilF.Unwrap())
	}
	if (&OverlapFailure{Phase: OverlapPhaseSeal}).Error() != "clustercreate: overlap failure" {
		t.Fatal("nil Err should use the fallback message")
	}
	if got, ok := AsOverlapFailure(fmt.Errorf("wrapped: %w", f)); !ok || got.Phase != OverlapPhasePromote {
		t.Fatalf("AsOverlapFailure(wrapped) = %+v, %v", got, ok)
	}
	if _, ok := AsOverlapFailure(errors.New("plain")); ok {
		t.Fatal("AsOverlapFailure(plain) should be false")
	}
	if got := FormatSealError(base); got != "cluster: store secret ref: boom" {
		t.Fatalf("FormatSealError = %q", got)
	}
	if got := FormatPromoteError(base); got != "cluster: placement commit failed: boom" {
		t.Fatalf("FormatPromoteError = %q", got)
	}
	if errString(nil) != "" || errString(base) != "boom" {
		t.Fatalf("errString: %q / %q", errString(nil), errString(base))
	}
}
