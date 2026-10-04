package clustercreate

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestPrepareRejectsReservedNames pins that a reserved name is refused before
// the reservation claims it in Raft.
func TestPrepareRejectsReservedNames(t *testing.T) {
	for _, name := range []string{"owner:abc/agent", "sb-0123456789abcdef"} {
		t.Run(name, func(t *testing.T) {
			stub := &clusterStub{
				Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
				selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
			}
			svc := testServiceWithCluster(stub)
			r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
			w := httptest.NewRecorder()
			if _, ok := Prepare(w, r, svc, models.CreateSandboxRequest{Image: "alpine:3.20", Name: name}, nil, PrepareOptions{}); ok {
				t.Fatal("Prepare accepted a reserved name")
			}
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if len(stub.reserveCalls) != 0 {
				t.Fatalf("ReserveOnTarget calls = %d, want 0", len(stub.reserveCalls))
			}
		})
	}
}

// TestPrepareReservesOwnerQualifiedName pins D4 on the cluster create path:
// the reservation claims the caller's owner-qualified key, also for facades
// that leave the reservation's secret handle untenanted.
func TestPrepareReservesOwnerQualifiedName(t *testing.T) {
	tests := []struct {
		name     string
		access   *controlplane.Access
		opts     PrepareOptions
		wantName string
	}{
		{name: "operator keeps plain name", access: &controlplane.Access{Operator: true}, wantName: "agent"},
		{name: "internal caller keeps plain name", wantName: "agent"},
		{name: "tenant via v1", access: &controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acct-a"}}, opts: PrepareOptions{OwnerRef: "acct-a"}, wantName: cluster.QualifiedSandboxName("acct-a", "agent")},
		{name: "tenant via facade", access: &controlplane.Access{Identity: controlplane.Identity{OwnerRef: "acct-a"}}, wantName: cluster.QualifiedSandboxName("acct-a", "agent")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &clusterStub{
				Noop:         cluster.NewNoop("node-a", "http://node-a", ""),
				selectTarget: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
			}
			svc := testServiceWithCluster(stub)
			r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
			if tt.access != nil {
				r = r.WithContext(controlplane.ContextWithAccess(r.Context(), *tt.access))
			}
			w := httptest.NewRecorder()
			req := models.CreateSandboxRequest{Image: "alpine:3.20", Name: "agent"}
			if _, ok := Prepare(w, r, svc, req, nil, tt.opts); !ok {
				t.Fatalf("Prepare failed: %d %s", w.Code, w.Body.String())
			}
			if len(stub.reserveCalls) != 1 {
				t.Fatalf("ReserveOnTarget calls = %d, want 1", len(stub.reserveCalls))
			}
			if got := stub.reserveCalls[0].redacted.Name; got != tt.wantName {
				t.Fatalf("reserved name = %q, want %q", got, tt.wantName)
			}
			if got := stub.reserveCalls[0].secrets.OwnerRef; got != tt.opts.OwnerRef {
				t.Fatalf("reservation secret owner = %q, want %q (unchanged)", got, tt.opts.OwnerRef)
			}
			if req.Name != "agent" {
				t.Fatalf("caller's request was mutated: %q", req.Name)
			}
		})
	}
}
