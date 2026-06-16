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

	reserveErr   error
	reserveCalls []reserveCall

	recordErr   error
	recordCalls []recordCall
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
	s.recordCalls = append(s.recordCalls, recordCall{sandboxID: sandboxID, spec: spec, secrets: secrets})
	return s.recordErr
}

type fakeRuntime struct {
	mu     sync.Mutex
	states map[string]*models.SandboxRuntimeState
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{states: map[string]*models.SandboxRuntimeState{}}
}

func (f *fakeRuntime) Create(_ context.Context, _ models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
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
	svc := service.New(cfg, logger, st, newFakeRuntime(), nil, caddy.New(cfg), cipher, mgr, nil)
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
		if stub.cancels != 1 {
			t.Fatalf("CancelReservation calls = %d, want 1", stub.cancels)
		}
		if len(stub.recordCalls) != 0 {
			t.Fatalf("RecordPlacement calls = %d, want 0", len(stub.recordCalls))
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
