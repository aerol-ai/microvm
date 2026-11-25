package clustercreate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestPrepareRefusalNamesOfferedRuntimes: when no worker can take a create,
// the router answers as before (503 with Retry-After), and when the create
// asked for a runtime no worker offers, the answer names the runtimes that
// are offered. Names only: the worker's id and name never appear. A runtime
// that is offered (the cluster is only full) is answered as before.
func TestPrepareRefusalNamesOfferedRuntimes(t *testing.T) {
	worker := cluster.Member{NodeID: "w-1", NodeName: "name-w-1", Role: "worker", Alive: true,
		Capacity: capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeGvisor}}}
	for _, tc := range []struct {
		name    string
		req     models.CreateSandboxRequest
		explain bool
	}{
		{name: "runtime no worker offers", req: models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeFirecracker}, explain: true},
		// A local-only image takes the router's other placement call.
		{name: "local-only image, runtime no worker offers", req: models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeWasm,
			ImageDistributionMode: models.ImageDistributionLocalOnly}, explain: true},
		{name: "local-only image, offered runtime", req: models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeDocker,
			ImageDistributionMode: models.ImageDistributionLocalOnly}},
		{name: "offered runtime, cluster full", req: models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeGvisor}},
		{name: "no runtime named", req: models.CreateSandboxRequest{Image: "alpine:3.20"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The router is an ingress node, so it never creates locally.
			router := cluster.Member{NodeID: "gw", Role: "ingress", Alive: true}
			stub := &clusterStub{Noop: cluster.NewNoop("gw", "", ""), selectErr: cluster.ErrNoPlacementTarget, members: []cluster.Member{router, worker}}
			svc := testServiceWithCluster(stub)
			w := httptest.NewRecorder()
			if _, ok := Prepare(w, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc, tc.req, apihttp.WriteErrorCode, PrepareOptions{}); ok {
				t.Fatal("Prepare returned ok=true, want a refusal")
			}
			body := w.Body.String()
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "30" || !strings.Contains(body, cluster.ErrNoPlacementTarget.Error()) {
				t.Fatalf("answer = %d Retry-After=%q %s, want the 503 it always gave", w.Code, w.Header().Get("Retry-After"), body)
			}
			want := `is not offered here (offered: docker, gvisor)`
			if strings.Contains(body, want) != tc.explain {
				t.Fatalf("body = %s, want offered list %v", body, tc.explain)
			}
			if strings.Contains(body, "w-1") {
				t.Fatalf("body names a node: %s", body)
			}
		})
	}
}
