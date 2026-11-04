package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// firewallOffRuntime is a containerd driver on a node whose host firewall is
// off: it reports NetRulesEnabled false, as the real driver does over a
// disabled netrules manager.
type firewallOffRuntime struct{ *apiRecordingRuntime }

func (firewallOffRuntime) NetRulesEnabled() bool { return false }

// POST /v1/sandboxes on a node without the host firewall: a create asking
// for network policy is a 501 with a stable code and nothing is built; a
// create without one still works, so local development is unaffected.
func TestCreateSandboxNetworkPolicyUnenforcedIs501(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarnessWithConfig(t, rt, cluster.NewNoop("node-a", "http://node-a", ""), func(c *config.Config) {
		c.ContainerEngine = models.ContainerEngineContainerd
	})
	h.deps.Service.SetContainerdRuntime(firewallOffRuntime{rt})

	for _, body := range []string{
		`{"image":"alpine:3.20","network_block_all":true}`,
		`{"image":"alpine:3.20","network_deny_out":["1.1.1.1/32"]}`,
		`{"image":"alpine:3.20","network_allow_out":["pypi.org"]}`,
	} {
		rr := httptest.NewRecorder()
		h.createSandbox(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body)))
		if rr.Code != http.StatusNotImplemented {
			t.Fatalf("%s: status = %d, want 501; body=%s", body, rr.Code, rr.Body.String())
		}
		var resp models.ErrorResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Code != models.ErrorCodeNetworkPolicyUnenforced || !strings.Contains(resp.Error, "SB_ENABLE_NETWORK_RULES") {
			t.Fatalf("%s: body = %s", body, rr.Body.String())
		}
	}
	if rt.createCalls != 0 {
		t.Fatalf("createCalls = %d, want 0", rt.createCalls)
	}

	rr := httptest.NewRecorder()
	h.createSandbox(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("plain create: status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	if rows, _ := st.List(t.Context()); len(rows) != 1 {
		t.Fatalf("stored rows = %d, want only the plain sandbox", len(rows))
	}
}
