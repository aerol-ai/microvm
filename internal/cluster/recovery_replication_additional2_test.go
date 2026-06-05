package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryBlobPath(t *testing.T) {
	if p := recoveryBlobPath("foo/bar"); p != PublicInternalRecoveryPath+"foo%2Fbar" {
		t.Errorf("expected url encoded path, got %v", p)
	}
}

func TestFetchRecoveryBlobAndMembers(t *testing.T) {
	// mock gossip
	c := &Cluster{
		nodeID: "node1",
		gossip: &gossipNode{
			memberIndex: &gossipMemberIndex{
				members: map[string]Member{
					"node2": {NodeID: "node2", Alive: true, Role: "server", APIURL: "http://api"},
				},
			},
		},
	}
	if len(c.recoveryServerMembers()) != 1 {
		t.Errorf("expected 1 member")
	}
	c.httpClient = http.DefaultClient

	_, ok, _ := c.fetchRecoveryBlob(context.Background(), "ref1")
	if ok {
		t.Errorf("expected false")
	}
}

func TestStoreAndReplicateRecoveryBlob(t *testing.T) {
	c := &Cluster{
		nodeID: "node1",
		gossip: &gossipNode{
			memberIndex: &gossipMemberIndex{
				members: map[string]Member{
					"node2": {NodeID: "node2", Alive: true, Role: "server", APIURL: "http://api"},
				},
			},
		},
	}
	fsm := newPlacementFSM()
	fsm.recoveryStore = newPlacementRecoveryMemoryStore()
	c.fsm = fsm

	c.httpClient = http.DefaultClient
	blob, _ := newRecoveryBlob("sb1", placementRecovery{})
	err := c.storeAndReplicateRecoveryBlob(context.Background(), blob)
	// will fail during putRecoveryBlobToMember due to invalid url but covers logic
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestReplicateRecoveryBlobAgent(t *testing.T) {
	a := &Agent{
		gossip: &gossipNode{
			memberIndex: &gossipMemberIndex{
				members: map[string]Member{
					"node2": {NodeID: "node2", Alive: true, Role: "server", APIURL: "http://api"},
				},
			},
		},
	}
	a.httpClient = http.DefaultClient
	// has members now
	err := a.replicateRecoveryBlob(context.Background(), RecoveryBlob{})
	if err == nil {
		t.Errorf("expected error from http put")
	}
}

func TestPutAndGetRecoveryBlobToMember(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(RecoveryBlob{Ref: "test-ref"})
		} else if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer ts.Close()

	c := &Cluster{httpClient: ts.Client()}
	a := &Agent{httpClient: ts.Client()}

	m := Member{APIURL: ts.URL}
	blob := RecoveryBlob{Ref: "test-ref"}

	err := c.putRecoveryBlobToMember(context.Background(), m, blob)
	if err != nil {
		t.Errorf("cluster put error: %v", err)
	}
	err = a.putRecoveryBlobToMember(context.Background(), m, blob)
	if err != nil {
		t.Errorf("agent put error: %v", err)
	}

	out, ok, err := c.getRecoveryBlobFromMember(context.Background(), m, "test-ref")
	if err != nil || !ok || out.Ref != "test-ref" {
		t.Errorf("get error: %v %v %v", out, ok, err)
	}

	// Internal client test
	c.internalClient = ts.Client()
	a.internalClient = ts.Client()
	m2 := Member{InternalURL: ts.URL}

	err = c.putRecoveryBlobToMember(context.Background(), m2, blob)
	if err != nil {
		t.Errorf("cluster put internal error: %v", err)
	}
	err = a.putRecoveryBlobToMember(context.Background(), m2, blob)
	if err != nil {
		t.Errorf("agent put internal error: %v", err)
	}

	out, ok, err = c.getRecoveryBlobFromMember(context.Background(), m2, "test-ref")
	if err != nil || !ok || out.Ref != "test-ref" {
		t.Errorf("get internal error: %v %v %v", out, ok, err)
	}

	// No URL test
	m3 := Member{}
	err = c.putRecoveryBlobToMember(context.Background(), m3, blob)
	if err == nil {
		t.Errorf("expected error")
	}
	err = a.putRecoveryBlobToMember(context.Background(), m3, blob)
	if err == nil {
		t.Errorf("expected error")
	}
	_, ok, err = c.getRecoveryBlobFromMember(context.Background(), m3, "test-ref")
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestExternalizeCommandRecoveryAgentsAndClusters(t *testing.T) {
	c := &Cluster{}
	c.fsm = newPlacementFSM()
	c.fsm.recoveryStore = newPlacementRecoveryMemoryStore()
	_, _ = c.externalizeCommandRecovery(context.Background(), command{})

	a := &Agent{}
	// will fail due to no members, but covers wrapper
	_, _ = a.externalizeCommandRecovery(context.Background(), command{Op: opPlace, SandboxID: "sb1"})
}
