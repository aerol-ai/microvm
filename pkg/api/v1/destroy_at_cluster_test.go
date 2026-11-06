package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestSelectedNodeCreateReplicatesDestroyAtAsAnAge (plan L6): the spec the
// owner promotes carries destroy_at_age, never destroy_at, so a failover
// recreate replays an age; a past destroy_at is a 400 before any work.
func TestSelectedNodeCreateReplicatesDestroyAtAsAnAge(t *testing.T) {
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, &apiRecordingRuntime{}, stub)
	at := time.Now().UTC().Add(time.Hour)
	rr := httptest.NewRecorder()
	h.createSandboxOnSelectedNode(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil),
		models.CreateSandboxRequest{Image: "alpine:3.20", Lifecycle: &models.Lifecycle{DestroyAt: &at}}, "sb-at")
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	if len(stub.recordSpecs) != 1 || stub.recordSpecs[0].Lifecycle == nil {
		t.Fatalf("promoted specs = %+v", stub.recordSpecs)
	}
	spec := stub.recordSpecs[0].Lifecycle
	if spec.DestroyAt != nil || spec.DestroyAtAge <= 59*time.Minute || spec.DestroyAtAge > time.Hour {
		t.Fatalf("promoted lifecycle = %+v, want an age of about an hour", spec)
	}

	past := time.Now().UTC().Add(-time.Minute)
	rr = httptest.NewRecorder()
	h.createSandboxOnSelectedNode(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil),
		models.CreateSandboxRequest{Image: "alpine:3.20", Lifecycle: &models.Lifecycle{DestroyAt: &past}}, "sb-past")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "destroy_at") {
		t.Fatalf("past destroy_at = %d %s", rr.Code, rr.Body.String())
	}
}

// TestClusterCreateRefusesAPastDestroyAtBeforeReserving: a refused
// destroy_at is a 400 before Prepare writes a reservation, so a corrected
// retry with the same name is not held off by it. A good one reaches the
// reservation as an age.
func TestClusterCreateRefusesAPastDestroyAtBeforeReserving(t *testing.T) {
	fake := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		target: cluster.PlacementTarget{NodeID: "node-a", APIURL: "http://node-a", IsSelf: true},
	}
	h, _ := newClusterCreateHarness(t, &apiRecordingRuntime{}, fake)
	body := func(at time.Time) *strings.Reader {
		return strings.NewReader(`{"image":"alpine:3.20","name":"job","lifecycle":{"destroy_at":"` + at.Format(time.RFC3339) + `"}}`)
	}
	rr := httptest.NewRecorder()
	h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", body(time.Now().Add(-time.Minute))))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "destroy_at") {
		t.Fatalf("past destroy_at = %d %s", rr.Code, rr.Body.String())
	}
	if len(fake.reserveCalls) != 0 {
		t.Fatalf("a refused destroy_at wrote %d reservations", len(fake.reserveCalls))
	}
	rr = httptest.NewRecorder()
	h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", body(time.Now().Add(time.Hour))))
	if rr.Code != http.StatusCreated {
		t.Fatalf("corrected retry = %d %s", rr.Code, rr.Body.String())
	}
	if len(fake.reserveCalls) != 1 {
		t.Fatalf("reserve calls = %d, want 1", len(fake.reserveCalls))
	}
	if l := fake.reserveCalls[0].redacted.Lifecycle; l == nil || l.DestroyAt != nil || l.DestroyAtAge <= 58*time.Minute {
		t.Fatalf("reserved lifecycle = %+v, want an age of about an hour", l)
	}
}
