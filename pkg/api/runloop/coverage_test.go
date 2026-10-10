package runloop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// mockCluster implements just the cluster.Client surface the facade's
// forwarding and list paths call; anything else panics on the nil embed.
type mockCluster struct {
	cluster.Client
	owner         cluster.OwnerInfo
	ownerErr      error
	forwardCalled bool
	page          cluster.PlacementPageResponse
}

func (m *mockCluster) OwnerOf(string) (cluster.OwnerInfo, error) { return m.owner, m.ownerErr }
func (m *mockCluster) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, _ *http.Request) {
	m.forwardCalled = true
	w.WriteHeader(http.StatusAccepted)
}
func (m *mockCluster) PlacementPage(cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	return m.page
}
func (m *mockCluster) SelfNodeID() string        { return "self" }
func (m *mockCluster) Members() []cluster.Member { return nil }
func (m *mockCluster) IsNodeDrained(string) bool { return false }

func TestClusterForwardWrap(t *testing.T) {
	local := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	withCluster := func(c cluster.Client) *service.Service {
		s := &service.Service{}
		s.AttachCluster(c)
		return s
	}
	cases := []struct {
		name        string
		svc         *service.Service
		header      string
		want        int
		wantForward bool
	}{
		{name: "no service", want: http.StatusOK},
		{name: "no cluster", svc: &service.Service{}, want: http.StatusOK},
		{name: "unknown", svc: withCluster(&mockCluster{ownerErr: cluster.ErrUnknownSandbox}), want: http.StatusOK},
		{name: "orphaned", svc: withCluster(&mockCluster{ownerErr: cluster.ErrOrphaned}), want: http.StatusGone},
		{name: "lookup error", svc: withCluster(&mockCluster{ownerErr: errors.New("boom")}), want: http.StatusServiceUnavailable},
		{name: "self", svc: withCluster(&mockCluster{owner: cluster.OwnerInfo{IsSelf: true}}), want: http.StatusOK},
		{name: "no urls", svc: withCluster(&mockCluster{owner: cluster.OwnerInfo{NodeID: "n1"}}), want: http.StatusServiceUnavailable},
		{name: "loop", svc: withCluster(&mockCluster{owner: cluster.OwnerInfo{NodeID: "n1", InternalURL: "https://n1"}}), header: "1", want: http.StatusMisdirectedRequest},
		{name: "forward", svc: withCluster(&mockCluster{owner: cluster.OwnerInfo{NodeID: "n1", InternalURL: "https://n1"}}), want: http.StatusAccepted, wantForward: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &handlers{deps: Deps{Service: tc.svc}}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.SetPathValue("id", "sb-1")
			if tc.header != "" {
				req.Header.Set("X-Cluster-Forwarded", tc.header)
			}
			rr := httptest.NewRecorder()
			h.clusterForwardWrap(local).ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d", rr.Code, tc.want)
			}
			if tc.wantForward {
				if !tc.svc.Cluster().(*mockCluster).forwardCalled {
					t.Fatal("request was not forwarded")
				}
			}
		})
	}
}

func TestListDevboxesInClusterMode(t *testing.T) {
	env := newTestEnv(t)
	a := env.mustCreate(t, "")
	b := env.mustCreate(t, "")
	first, second := a.ID, b.ID
	if second < first {
		first, second = second, first
	}
	mc := &mockCluster{page: cluster.PlacementPageResponse{
		Authoritative: true,
		Placements:    []cluster.Placement{{SandboxID: first, OwnerNodeID: "self"}},
		NextPageToken: first,
	}}
	env.svc.AttachCluster(mc)

	var page listDevboxesResponse
	rr := env.do(t, http.MethodGet, "?limit=1", nil, &page)
	expectStatus(t, rr, http.StatusOK)
	if len(page.Devboxes) != 1 || page.Devboxes[0].ID != first || !page.HasMore || page.TotalCount != nil {
		t.Fatalf("cluster page = %+v", page)
	}

	// Cold placement index on a small fleet: page locally by id.
	mc.page = cluster.PlacementPageResponse{}
	expectStatus(t, env.do(t, http.MethodGet, "?limit=1", nil, &page), http.StatusOK)
	if len(page.Devboxes) != 1 || page.Devboxes[0].ID != first || !page.HasMore {
		t.Fatalf("cold page = %+v", page)
	}
	q, _ := url.ParseQuery("limit=2&starting_after=x&include_total_count=true&status=running&nextToken=1")
	if got := stripListPaging(q); got != "status=running" {
		t.Fatalf("stripListPaging = %q", got)
	}
}

func TestWriteStoreAwareErrorMapping(t *testing.T) {
	cases := []struct {
		err       error
		status    int
		retryable bool
	}{
		{badRequest("x"), http.StatusBadRequest, true},
		{notFound("x"), http.StatusNotFound, true},
		{store.ErrNotFound, http.StatusNotFound, true},
		{service.ErrSandboxManuallyStopped, http.StatusConflict, false},
		{service.ErrPublicTrafficDisabled, http.StatusConflict, false},
		{service.ErrWakeCircuitOpen, http.StatusServiceUnavailable, true},
		{service.ErrEgressOperatorConfigInvalid, http.StatusServiceUnavailable, true},
		{service.ErrEgressGatewayUnavailable, http.StatusServiceUnavailable, true},
		{models.ErrRuntimeNotImplemented, http.StatusNotImplemented, false},
		{store.ErrSnapshotNameConflict, http.StatusConflict, false},
		{models.ErrSandboxExists, http.StatusConflict, false},
		{capacity.ErrCapacityExceeded, http.StatusServiceUnavailable, true},
		{cluster.ErrCreateBackpressure, http.StatusTooManyRequests, true},
		{cluster.ErrNoPlacementTarget, http.StatusServiceUnavailable, true},
		{cluster.ErrInvalidTopology, http.StatusServiceUnavailable, true},
		{errors.New(strings.Repeat("x", 300)), http.StatusBadRequest, true},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range cases {
		rr := httptest.NewRecorder()
		writeStoreAwareError(logger, rr, fmt.Errorf("wrapped: %w", tc.err))
		if rr.Code != tc.status {
			t.Fatalf("%v → %d, want %d", tc.err, rr.Code, tc.status)
		}
		if retry := rr.Header().Get("x-should-retry") != "false"; retry != tc.retryable {
			t.Fatalf("%v: retryable = %v, want %v", tc.err, retry, tc.retryable)
		}
		var body errorResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Message == "" || len(body.Message) > 200 {
			t.Fatalf("%v: body %q", tc.err, rr.Body.String())
		}
	}
	if (requestError{status: 400, message: "m"}).Error() != "m" {
		t.Fatal("requestError.Error")
	}
}

func TestResources(t *testing.T) {
	str := func(s string) *string { return &s }
	f := func(v float64) *float64 { return &v }
	i := func(v int) *int { return &v }
	cases := []struct {
		name    string
		lp      *launchParameters
		cpu     float64
		mem, gb int
		wantErr bool
	}{
		{name: "none", lp: nil},
		{name: "empty", lp: &launchParameters{}},
		{name: "preset", lp: &launchParameters{ResourceSizeRequest: str("x_small")}, cpu: 0.5, mem: 1024, gb: 4},
		{name: "custom", lp: &launchParameters{ResourceSizeRequest: str("CUSTOM_SIZE"), CustomCPUCores: f(0.5), CustomGBMemory: i(2), CustomDiskSize: i(6)}, cpu: 0.5, mem: 2048, gb: 6},
		{name: "custom no disk", lp: &launchParameters{ResourceSizeRequest: str("CUSTOM_SIZE"), CustomCPUCores: f(1), CustomGBMemory: i(2)}, cpu: 1, mem: 2048},
		{name: "custom without size", lp: &launchParameters{CustomCPUCores: f(1)}, wantErr: true},
		{name: "custom zero", lp: &launchParameters{ResourceSizeRequest: str("CUSTOM_SIZE"), CustomCPUCores: f(0), CustomGBMemory: i(2)}, wantErr: true},
		{name: "custom bad disk", lp: &launchParameters{ResourceSizeRequest: str("CUSTOM_SIZE"), CustomCPUCores: f(1), CustomGBMemory: i(2), CustomDiskSize: i(-1)}, wantErr: true},
		{name: "unknown", lp: &launchParameters{ResourceSizeRequest: str("GIANT")}, wantErr: true},
	}
	for _, tc := range cases {
		cpu, mem, gb, err := resources(tc.lp)
		if (err != nil) != tc.wantErr || cpu != tc.cpu || mem != tc.mem || gb != tc.gb {
			t.Fatalf("%s: got %v %d %d %v", tc.name, cpu, mem, gb, err)
		}
	}
}

func TestLifecycleFor(t *testing.T) {
	i := func(v int) *int { return &v }
	idle := func(s int, on string) *afterIdle { return &afterIdle{IdleTimeSeconds: s, OnIdle: on} }
	cases := []struct {
		name    string
		lp      *launchParameters
		want    models.Lifecycle
		wantErr bool
	}{
		{name: "default", lp: nil, want: models.Lifecycle{DestroyAtAge: time.Hour}},
		{name: "keep alive", lp: &launchParameters{KeepAliveTimeSeconds: i(60)}, want: models.Lifecycle{DestroyAtAge: time.Minute}},
		{name: "idle shutdown", lp: &launchParameters{AfterIdle: idle(30, "shutdown"), KeepAliveTimeSeconds: i(60)}, want: models.Lifecycle{DestroyIfIdleFor: 30 * time.Second}},
		{name: "lifecycle idle", lp: &launchParameters{Lifecycle: &lifecycleParams{AfterIdle: idle(30, "suspend")}}, want: models.Lifecycle{StopIfIdleFor: 30 * time.Second}},
		{name: "both equal", lp: &launchParameters{AfterIdle: idle(30, "suspend"), Lifecycle: &lifecycleParams{AfterIdle: idle(30, "suspend")}}, want: models.Lifecycle{StopIfIdleFor: 30 * time.Second}},
		{name: "both differ", lp: &launchParameters{AfterIdle: idle(30, "suspend"), Lifecycle: &lifecycleParams{AfterIdle: idle(31, "suspend")}}, wantErr: true},
		{name: "zero idle", lp: &launchParameters{AfterIdle: idle(0, "suspend")}, wantErr: true},
		{name: "zero keep alive", lp: &launchParameters{KeepAliveTimeSeconds: i(0)}, wantErr: true},
	}
	for _, tc := range cases {
		got, err := lifecycleFor(tc.lp)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
		if err == nil && *got != tc.want {
			t.Fatalf("%s: got %+v want %+v", tc.name, *got, tc.want)
		}
	}
}

func TestUnsupportedCreateFields(t *testing.T) {
	var req createDevboxRequest
	raw := `{"entrypoint":"x","secrets":{"a":"b"},"file_mounts":{"/a":"b"},"mounts":[{"type":"object_mount"}],
		"code_mounts":[{"repo_name":"r"}],"tunnel":{"auth_mode":"open"},"gateways":{"G":{}},"mcp":{"M":{}},
		"launch_parameters":{"launch_commands":["ls"],"user_parameters":{"uid":1},"network_policy_id":"np",
		"required_services":["db"],"provisioning_tier":"flex",
		"lifecycle":{"lifecycle_hooks":{"suspend_commands":["x"]},"resume_triggers":{"http":true}}}}`
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatal(err)
	}
	if got := unsupportedCreateFields(req); len(got) != 15 {
		t.Fatalf("unsupported = %v (%d)", got, len(got))
	}
	var empty createDevboxRequest
	if err := json.Unmarshal([]byte(`{"mounts":[],"tunnel":null,"launch_parameters":{"provisioning_tier":"standard","lifecycle":{"resume_triggers":{"http":false}}}}`), &empty); err != nil {
		t.Fatal(err)
	}
	if got := unsupportedCreateFields(empty); len(got) != 0 {
		t.Fatalf("empty values flagged: %v", got)
	}
}

func TestMetaHelpers(t *testing.T) {
	if unixMillis(time.Time{}) != 0 {
		t.Fatal("zero time")
	}
	if _, err := decodeDevboxBlob(&models.SandboxCompatState{StateJSON: "{"}); err == nil {
		t.Fatal("bad blob decoded")
	}
	t.Setenv(blueprintMapEnv, "{bad")
	if got := loadBlueprintMap(slog.New(slog.NewTextHandler(io.Discard, nil))); got[defaultBlueprintKey] != defaultImage || len(got) != 1 {
		t.Fatalf("invalid map = %v", got)
	}
	t.Setenv(blueprintMapEnv, `{"default":"debian:12"," ":"x"}`)
	if got := loadBlueprintMap(nil); got[defaultBlueprintKey] != "debian:12" || len(got) != 1 {
		t.Fatalf("override map = %v", got)
	}
	if holdFor(nil, time.Second) != time.Second {
		t.Fatal("holdFor nil")
	}
	big := 100.0
	if holdFor(&big, time.Second) != time.Second {
		t.Fatal("holdFor cap")
	}
	if err := decodeJSONBytes([]byte(`{} {}`), &struct{}{}); err == nil {
		t.Fatal("two JSON values accepted")
	}
}

func TestRegisterRoutesAppliesAuth(t *testing.T) {
	env := newTestEnv(t)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: env.svc, Auth: func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			WriteError(w, http.StatusUnauthorized, "unauthorized")
		})
	}})
	for _, path := range []string{devboxesPath, devboxesPath + "/sb-1"} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d", path, rr.Code)
		}
	}
}

func TestSnapshotInProgress(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	old := snapshotHold
	snapshotHold = 20 * time.Millisecond
	t.Cleanup(func() { snapshotHold = old })
	env.runtime.blockSnapshot = make(chan struct{})

	var pending snapshotView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk_async", `{"name":"slow","metadata":{"k":"v"}}`, &pending), http.StatusOK)
	if pending.Name == nil || *pending.Name != "slow" || pending.Metadata["k"] != "v" || pending.SourceDevboxID != devbox.ID {
		t.Fatalf("pending = %+v", pending)
	}
	var status snapshotStatusView
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/"+pending.ID+"/status", nil, &status), http.StatusOK)
	if status.Status != "in_progress" {
		t.Fatalf("status = %+v", status)
	}
	close(env.runtime.blockSnapshot)
	waitFor(t, "snapshot completion", func() bool {
		var s snapshotStatusView
		env.do(t, http.MethodGet, "/disk_snapshots/"+pending.ID+"/status", nil, &s)
		return s.Status == "complete"
	})
}

func TestRetryOfUnsubmittedExecutionConflicts(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	old := submitWait
	submitWait = 30 * time.Millisecond
	t.Cleanup(func() { submitWait = old })
	// Simulate an original request that claimed the session and died.
	sid := ephemeralPrefix + shortHash(devbox.ID, "dead")
	if _, err := env.h.createSession(context.Background(), devbox.ID, sid); err != nil {
		t.Fatal(err)
	}
	rr := env.do(t, http.MethodPost, "/"+devbox.ID+"/execute", `{"command":"echo x","command_id":"dead"}`, nil)
	expectStatus(t, rr, http.StatusConflict)
	if rr.Header().Get("x-should-retry") != "false" {
		t.Fatal("conflict must not be retried")
	}
}
