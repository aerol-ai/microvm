package v1

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// runtimesCluster holds members' capacity as a server's lease overlay does.
// It refuses any per-member drained lookup: on a worker that would be one
// control-plane call per member on the request path.
type runtimesCluster struct {
	*cluster.Noop
	members []cluster.Member
}

func (c *runtimesCluster) Members() []cluster.Member     { return c.members }
func (c *runtimesCluster) DrainedNodes() map[string]bool { return map[string]bool{"w-drained": true} }
func (c *runtimesCluster) IsNodeDrained(string) bool {
	panic("GET /v1/runtimes asked IsNodeDrained per member")
}

func runtimesWorker(id string, runtimes ...string) cluster.Member {
	return cluster.Member{NodeID: id, NodeName: "name-" + id, Role: "worker", Alive: true,
		Capacity: capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, SupportedRuntimes: runtimes}}
}

// newRuntimesMux mounts the v1 routes on a service: single-node with the
// given host runtimes, or a cluster with members. access is read per
// request, so one mux serves every caller in a table.
func newRuntimesMux(t *testing.T, hostRuntimes []string, members []cluster.Member, access *controlplane.Access) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	admitter := capacity.New(capacity.HostInfo{CPUCores: 4, MemoryTotalMB: 8192, SupportedRuntimes: hostRuntimes}, capacity.Limits{}, nil)
	svc := service.New(config.Config{EnableCluster: members != nil}, logger, nil, nil, nil, nil, nil, nil, admitter)
	if members != nil {
		svc.AttachCluster(&runtimesCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), members: members})
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), *access)))
		})
	}})
	return mux
}

func getRuntimes(t *testing.T, h http.Handler) (models.ListRuntimesResponse, string) {
	t.Helper()
	rr := do(t, h, http.MethodGet, "/v1/runtimes", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/runtimes = %d %s", rr.Code, rr.Body.String())
	}
	var out models.ListRuntimesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out, rr.Body.String()
}

// TestListRuntimes covers both deployment shapes and both kinds of caller.
// Every caller sees every runtime a create accepts, with its features and
// whether it is offered; only fleet admins see node counts; nobody sees a
// node's id or name.
func TestListRuntimes(t *testing.T) {
	tenant := controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef("payments")},
		Role:      controlplane.RoleViewer,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_team"},
	}
	members := []cluster.Member{
		runtimesWorker("w-1", models.RuntimeDocker, models.RuntimeFirecracker),
		runtimesWorker("w-2", models.RuntimeDocker, models.RuntimeGvisor),
		runtimesWorker("w-drained", models.RuntimeWasm),
		{NodeID: "srv-1", NodeName: "name-srv-1", Role: "server", Alive: true,
			Capacity: capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, SupportedRuntimes: []string{models.RuntimeIsolate}}},
	}
	for _, tc := range []struct {
		name      string
		host      []string
		members   []cluster.Member
		access    controlplane.Access
		available map[string]int // runtime -> nodes, for the runtimes offered
		withNodes bool
	}{
		{name: "single node, tenant", host: []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeKata},
			access: tenant, available: map[string]int{models.RuntimeDocker: 1, models.RuntimeGvisor: 1}},
		{name: "single node, fleet admin", host: []string{models.RuntimeDocker, models.RuntimeGvisor},
			access: fleetToken(controlplane.RoleAdmin), withNodes: true,
			available: map[string]int{models.RuntimeDocker: 1, models.RuntimeGvisor: 1}},
		{name: "cluster, tenant", members: members, access: tenant,
			available: map[string]int{models.RuntimeDocker: 2, models.RuntimeFirecracker: 1, models.RuntimeGvisor: 1}},
		{name: "cluster, fleet viewer", members: members, access: fleetToken(controlplane.RoleViewer),
			available: map[string]int{models.RuntimeDocker: 2, models.RuntimeFirecracker: 1, models.RuntimeGvisor: 1}},
		{name: "cluster, fleet admin", members: members, access: fleetToken(controlplane.RoleAdmin), withNodes: true,
			available: map[string]int{models.RuntimeDocker: 2, models.RuntimeFirecracker: 1, models.RuntimeGvisor: 1}},
		{name: "cluster, operator", members: members, access: controlplane.OperatorAccess(), withNodes: true,
			available: map[string]int{models.RuntimeDocker: 2, models.RuntimeFirecracker: 1, models.RuntimeGvisor: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			access := tc.access
			got, body := getRuntimes(t, newRuntimesMux(t, tc.host, tc.members, &access))
			table := models.RuntimeTable()
			if len(got.Runtimes) != len(table) {
				t.Fatalf("listed %d runtimes, want %d: %s", len(got.Runtimes), len(table), body)
			}
			for i, entry := range got.Runtimes {
				if entry.Name != table[i].Name || entry.Features != table[i].Features || entry.Isolation != table[i].Isolation {
					t.Errorf("entry %d = %+v, want the table's row %+v", i, entry, table[i])
				}
				nodes, offered := tc.available[entry.Name]
				if entry.Available != offered {
					t.Errorf("%s available = %v, want %v", entry.Name, entry.Available, offered)
				}
				switch {
				case !tc.withNodes && entry.Nodes != nil:
					t.Errorf("%s: %s sees a node count", entry.Name, tc.name)
				case tc.withNodes && (entry.Nodes == nil || *entry.Nodes != nodes):
					t.Errorf("%s nodes = %v, want %d", entry.Name, entry.Nodes, nodes)
				}
			}
			for _, leak := range []string{"w-1", "name-w-1", "srv-1", "w-drained"} {
				if strings.Contains(body, leak) {
					t.Errorf("the body names a node (%q): %s", leak, body)
				}
			}
		})
	}
}

// TestListRuntimesRoute: the route reads with sandbox.read, so any caller
// that may read sandboxes may list runtimes, and a sandbox token (one verb
// on one sandbox) may not.
func TestListRuntimesRoute(t *testing.T) {
	for _, tc := range []struct {
		name   string
		access controlplane.Access
		want   int
	}{
		{"team viewer", controlplane.Access{Identity: controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef("payments")},
			Role: controlplane.RoleViewer, Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok"}}, http.StatusOK},
		{"sandbox token", controlplane.Access{Principal: controlplane.Principal{Kind: controlplane.PrincipalSandboxToken, ID: "sbt"}}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			access := tc.access
			rr := do(t, newRuntimesMux(t, nil, nil, &access), http.MethodGet, "/v1/runtimes", nil)
			if rr.Code != tc.want {
				t.Fatalf("GET /v1/runtimes = %d %s, want %d", rr.Code, rr.Body.String(), tc.want)
			}
		})
	}
}

// TestCreateRefusalNamesOfferedRuntimesOverHTTP: a create of a runtime this
// node does not offer keeps the status it had (501 for a runtime this build
// or node cannot run) and its body names the runtimes that are offered,
// with no node named.
func TestCreateRefusalNamesOfferedRuntimesOverHTTP(t *testing.T) {
	tenant := controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef("payments")},
		Role:      controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_team"},
	}
	for _, runtime := range []string{models.RuntimeKata, models.RuntimeFirecracker, models.RuntimeWasm, models.RuntimeIsolate} {
		t.Run(runtime, func(t *testing.T) {
			mux := newRefusalMux(t, []string{models.RuntimeDocker, models.RuntimeGvisor}, tenant)
			rr := do(t, mux, http.MethodPost, "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "runtime": runtime})
			if rr.Code != http.StatusNotImplemented {
				t.Fatalf("POST /v1/sandboxes = %d %s, want 501 as before", rr.Code, rr.Body.String())
			}
			want := `runtime \"` + runtime + `\" is not offered here (offered: docker, gvisor)`
			if !strings.Contains(rr.Body.String(), want) {
				t.Fatalf("body = %s, want it to name the offered runtimes: %s", rr.Body.String(), want)
			}
		})
	}
}

// newRefusalMux is a single node with a store and no runtime driver: enough
// for a create to reach its runtime checks and be refused there.
func newRefusalMux(t *testing.T, hostRuntimes []string, access controlplane.Access) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	admitter := capacity.New(capacity.HostInfo{CPUCores: 4, MemoryTotalMB: 8192, SupportedRuntimes: hostRuntimes}, capacity.Limits{}, nil)
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, admitter)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), access)))
		})
	}})
	return mux
}
