package clustercreate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

type afterReserveKey struct{}

// AfterReserve runs between the reservation and the create's node, with
// the reservation's id and the incarnation the router minted for it; its
// request is the one the create goes on with; a refusal cancels the
// reservation.
func TestPrepareAfterReserve(t *testing.T) {
	type seen struct{ id, inc string }
	hook := func(calls *[]seen, ok bool) func(http.ResponseWriter, *http.Request, string, string) (*http.Request, bool) {
		return func(w http.ResponseWriter, r *http.Request, id, inc string) (*http.Request, bool) {
			*calls = append(*calls, seen{id, inc})
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				return nil, false
			}
			return r.WithContext(context.WithValue(r.Context(), afterReserveKey{}, id)), true
		}
	}
	req := models.CreateSandboxRequest{Image: "alpine:3.20", CustomDomains: []string{"app.customer.com"}}

	t.Run("local", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true}}
		var calls []seen
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		decision, ok := Prepare(httptest.NewRecorder(), r, testServiceWithCluster(stub), req, nil,
			PrepareOptions{PreferredSandboxID: "sb-ar", AfterReserve: hook(&calls, true)})
		if !ok || len(calls) != 1 || calls[0].id != "sb-ar" || calls[0].inc == "" {
			t.Fatalf("ok=%v calls=%v", ok, calls)
		}
		if got := stub.reserveCalls[0].secrets.IncarnationID; got != calls[0].inc {
			t.Fatalf("reserved at %q, hook told %q", got, calls[0].inc)
		}
		if decision.Request(r).Context().Value(afterReserveKey{}) != "sb-ar" {
			t.Fatal("the local create does not go on with the hook's request")
		}
	})

	t.Run("remote", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b"}}
		var calls []seen
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), testServiceWithCluster(stub), req, nil,
			PrepareOptions{PreferredSandboxID: "sb-ar", AfterReserve: hook(&calls, true)})
		if ok || len(calls) != 1 || stub.forwards != 1 || stub.cancels != 0 {
			t.Fatalf("ok=%v calls=%v forwards=%d cancels=%d", ok, calls, stub.forwards, stub.cancels)
		}
	})

	t.Run("refused", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b"}}
		var calls []seen
		w := httptest.NewRecorder()
		_, ok := Prepare(w, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), testServiceWithCluster(stub), req, nil,
			PrepareOptions{PreferredSandboxID: "sb-ar", AfterReserve: hook(&calls, false)})
		if ok || w.Code != http.StatusForbidden || stub.forwards != 0 || stub.cancels != 1 {
			t.Fatalf("ok=%v status=%d forwards=%d cancels=%d", ok, w.Code, stub.forwards, stub.cancels)
		}
	})

	t.Run("no hook mints nothing", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true}}
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		decision, ok := Prepare(httptest.NewRecorder(), r, testServiceWithCluster(stub), req, nil, PrepareOptions{PreferredSandboxID: "sb-ar"})
		if !ok || stub.reserveCalls[0].secrets.IncarnationID != "" || decision.Request(r) != r {
			t.Fatalf("ok=%v secrets=%+v", ok, stub.reserveCalls[0].secrets)
		}
	})

	// An image only another node holds goes there with no reservation, so
	// there is nothing to bind its custom domains to.
	t.Run("node-local image with custom domains", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("server-a", "http://server-a", ""),
			selectTarget: cluster.PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b"},
			members:      []cluster.Member{{NodeID: "server-a", Role: config.NodeRoleServer}, {NodeID: "worker-b", Role: config.NodeRoleWorker}}}
		local := models.CreateSandboxRequest{Image: docker.BuiltImageNamespace + "/abc:latest", CustomDomains: []string{"app.customer.com"}}
		var calls []seen
		var status int
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), testServiceWithCluster(stub), local,
			func(_ http.ResponseWriter, code int, _, _ string) { status = code }, PrepareOptions{AfterReserve: hook(&calls, true)})
		if ok || status != http.StatusBadRequest || stub.forwards != 0 || len(calls) != 0 {
			t.Fatalf("ok=%v status=%d forwards=%d calls=%v", ok, status, stub.forwards, calls)
		}
		local.CustomDomains = nil
		if _, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), testServiceWithCluster(stub), local, nil,
			PrepareOptions{AfterReserve: hook(&calls, true)}); ok || stub.forwards != 1 {
			t.Fatalf("without custom domains: ok=%v forwards=%d", ok, stub.forwards)
		}
	})
}
