package clustercreate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Placement rules at the router (plans/placement-rules.md): the rule is
// validated and made canonical before placement, rides the forwarded body
// and the reservation's spec, and an unsatisfiable rule is a 409 with a code
// from whichever step found it.
func TestPreparePlacementRules(t *testing.T) {
	type answer struct {
		status int
		code   string
		msg    string
	}
	writer := func(a *answer) ErrorWriter {
		return func(_ http.ResponseWriter, status int, code, msg string) { *a = answer{status, code, msg} }
	}
	unsat := models.PlacementUnsatisfiableError(map[string]string{"zone": "zone-z"})

	t.Run("invalid rule is a 400 before placement", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
		var got answer
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), testServiceWithCluster(stub),
			models.CreateSandboxRequest{Image: "alpine", Placement: &models.PlacementRule{Zone: "z 1"}}, writer(&got), PrepareOptions{})
		if ok || got.status != http.StatusBadRequest || len(stub.selectReqs) != 0 {
			t.Fatalf("ok=%v answer=%+v selects=%d", ok, got, len(stub.selectReqs))
		}
	})

	for _, step := range []string{"select", "reserve"} {
		t.Run("unsatisfiable at "+step+" is a 409", func(t *testing.T) {
			stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), selectTarget: cluster.PlacementTarget{NodeID: "node-a", IsSelf: true}}
			if step == "select" {
				stub.selectErr = unsat
			} else {
				stub.reserveErr = unsat
			}
			var got answer
			_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), testServiceWithCluster(stub),
				models.CreateSandboxRequest{Image: "alpine", Placement: &models.PlacementRule{Zone: "zone-z"}}, writer(&got), PrepareOptions{})
			if ok || got.status != http.StatusConflict || got.code != models.ErrorCodePlacementUnsatisfiable || !strings.Contains(got.msg, "zone=zone-z") {
				t.Fatalf("ok=%v answer=%+v", ok, got)
			}
		})
	}

	t.Run("local-only image placement is a 409 too", func(t *testing.T) {
		// A server-role router cannot run the built image itself, so it
		// places it, and the rule's 409 comes from that placement.
		stub := &clusterStub{Noop: cluster.NewNoop("server-a", "http://server-a", ""), selectErr: unsat,
			members: []cluster.Member{{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer}}}
		var got answer
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), testServiceWithCluster(stub),
			models.CreateSandboxRequest{Image: docker.BuiltImageNamespace + "/abc:latest", Placement: &models.PlacementRule{Zone: "zone-z"}}, writer(&got), PrepareOptions{})
		if ok || got.status != http.StatusConflict || got.code != models.ErrorCodePlacementUnsatisfiable {
			t.Fatalf("ok=%v answer=%+v", ok, got)
		}
	})

	t.Run("canonical rule reaches placement, the forward and the reservation", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", ""), selectTarget: cluster.PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b"}}
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		_, ok := Prepare(httptest.NewRecorder(), r, testServiceWithCluster(stub),
			models.CreateSandboxRequest{Image: "alpine", Placement: &models.PlacementRule{Labels: map[string]string{"zone": "zone-a", "gpu": "a10"}}},
			nil, PrepareOptions{SyncBody: true})
		if ok {
			t.Fatal("a remote target must forward, not run locally")
		}
		want := map[string]string{"zone": "zone-a", "gpu": "a10"}
		if len(stub.selectReqs) != 1 || !reflect.DeepEqual(stub.selectReqs[0].Labels, want) {
			t.Fatalf("placement labels = %+v, want %v", stub.selectReqs, want)
		}
		if len(stub.reserveCalls) != 1 || stub.reserveCalls[0].redacted.Placement == nil || stub.reserveCalls[0].redacted.Placement.Zone != "zone-a" {
			t.Fatalf("reservation spec lost the rule: %+v", stub.reserveCalls)
		}
		body, _ := io.ReadAll(r.Body)
		var fwd models.CreateSandboxRequest
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&fwd); err != nil {
			t.Fatal(err)
		}
		if fwd.Placement == nil || fwd.Placement.Zone != "zone-a" || fwd.Placement.Labels["gpu"] != "a10" || fwd.Placement.Labels["zone"] != "" {
			t.Fatalf("forwarded rule = %+v, want canonical", fwd.Placement)
		}
	})
}

func TestCapacityRequestFromCreateCarriesPlacementLabels(t *testing.T) {
	got := CapacityRequestFromCreate(models.CreateSandboxRequest{Placement: &models.PlacementRule{Zone: "z1"}})
	if !reflect.DeepEqual(got.Labels, map[string]string{"zone": "z1"}) {
		t.Fatalf("Labels = %v", got.Labels)
	}
	if CapacityRequestFromCreate(models.CreateSandboxRequest{}).Labels != nil {
		t.Fatal("no rule must give no labels")
	}
	if !errors.Is(models.PlacementUnsatisfiableError(nil), cluster.ErrPlacementUnsatisfiable) {
		t.Fatal("cluster and models must share the sentinel")
	}
}
