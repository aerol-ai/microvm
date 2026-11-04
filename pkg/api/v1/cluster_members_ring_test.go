package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

type ringGateStub struct {
	*drainStubCluster
	ready bool
}

func (r ringGateStub) ServerKeyRingAllowed() bool { return r.ready }

// TestClusterMembersServerKeyRingReady: the members response carries the
// gossip gate `sandboxd key rotate --stage` waits on, and leaves it out for
// a client that cannot say, so an old daemon reads as "not ready".
func TestClusterMembersServerKeyRingReady(t *testing.T) {
	read := func(c cluster.Client) map[string]json.RawMessage {
		rr := httptest.NewRecorder()
		drainTestHandler(t, c).clusterMembers(rr, httptest.NewRequest(http.MethodGet, "/v1/cluster/members", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	base := &drainStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	for _, ready := range []bool{true, false} {
		body := read(ringGateStub{drainStubCluster: base, ready: ready})
		if got := string(body["server_key_ring_ready"]); got != map[bool]string{true: "true", false: "false"}[ready] {
			t.Fatalf("ready=%v: server_key_ring_ready = %s", ready, got)
		}
	}
	if _, ok := read(base)["server_key_ring_ready"]; ok {
		t.Fatal("a client without the gate reported one")
	}
}
