package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCommandCarriesRecoveryPayload(t *testing.T) {
	if commandCarriesRecoveryPayload(nil, "", 0) {
		t.Errorf("expected false")
	}
	if !commandCarriesRecoveryPayload(&models.CreateSandboxRequest{}, "", 0) {
		t.Errorf("expected true")
	}
	if !commandCarriesRecoveryPayload(nil, "ref", 0) {
		t.Errorf("secret ref alone should count as payload")
	}
	if !commandCarriesRecoveryPayload(nil, "", 2) {
		t.Errorf("secret version alone should count as payload")
	}
}

func TestRecoveryBlobPath(t *testing.T) {
	if p := recoveryBlobPath("foo/bar"); p != PublicInternalRecoveryPath+"foo%2Fbar" {
		t.Errorf("expected url encoded path, got %v", p)
	}
}

// seedRecoveryBlob puts rec into store and returns the served RecoveryBlob
// shape for its content-addressed ref.
func seedRecoveryBlob(t *testing.T, store placementRecoveryStore, sandboxID string, rec placementRecovery) RecoveryBlob {
	t.Helper()
	ref, err := store.Put(sandboxID, rec)
	if err != nil {
		t.Fatalf("seed recovery blob: %v", err)
	}
	record, ok, err := store.GetRecord(ref)
	if err != nil || !ok {
		t.Fatalf("read back seeded blob: ok=%v err=%v", ok, err)
	}
	return recoveryBlobFromRecord(ref, record)
}

// TestRecoveryBlobServeLocal covers the GET-serve half that peers hit on
// fetch-on-miss: a locally-stored payload is returned by ref; a Cluster with
// no FSM/store reports not-found instead of erroring.
func TestRecoveryBlobServeLocal(t *testing.T) {
	fsm := newPlacementFSM()
	c := &Cluster{fsm: fsm}

	blob := seedRecoveryBlob(t, fsm.recoveryStore, "sb1", placementRecovery{
		Spec: &models.CreateSandboxRequest{Name: "served", Image: "alpine:3.20"},
	})

	out, ok, err := c.RecoveryBlob(context.Background(), blob.Ref)
	if err != nil || !ok {
		t.Fatalf("failed to get blob: ok=%v err=%v", ok, err)
	}
	if out.Ref != blob.Ref || out.Spec == nil || out.Spec.Image != "alpine:3.20" {
		t.Errorf("served blob diverged: %+v", out)
	}

	c2 := &Cluster{}
	if _, ok, _ := c2.RecoveryBlob(context.Background(), blob.Ref); ok {
		t.Errorf("expected not ok without an fsm")
	}
}

func TestFetchRecoveryBlobAndMembers(t *testing.T) {
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

// TestFetchRecoveryBlobFromPeer is the client half of the snapshot-join
// fetch-on-miss path: a peer serving the GET endpoint satisfies the fetch.
func TestFetchRecoveryBlobFromPeer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(RecoveryBlob{Ref: "test-ref", SandboxID: "sb1"})
	}))
	defer ts.Close()

	c := &Cluster{
		nodeID:     "node1",
		httpClient: ts.Client(),
		gossip: &gossipNode{
			memberIndex: &gossipMemberIndex{
				members: map[string]Member{
					"node2": {NodeID: "node2", Alive: true, Role: "server", APIURL: ts.URL},
				},
			},
		},
	}
	blob, ok, err := c.fetchRecoveryBlob(context.Background(), "test-ref")
	if err != nil || !ok || blob.Ref != "test-ref" {
		t.Fatalf("fetch from peer: blob=%+v ok=%v err=%v", blob, ok, err)
	}
}

func TestGetRecoveryBlobFromMember(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(RecoveryBlob{Ref: "test-ref"})
	}))
	defer ts.Close()

	c := &Cluster{httpClient: ts.Client()}

	out, ok, err := c.getRecoveryBlobFromMember(context.Background(), Member{APIURL: ts.URL}, "test-ref")
	if err != nil || !ok || out.Ref != "test-ref" {
		t.Errorf("get error: %v %v %v", out, ok, err)
	}

	// Internal (mTLS) channel is preferred when present.
	c.internalClient = ts.Client()
	out, ok, err = c.getRecoveryBlobFromMember(context.Background(), Member{InternalURL: ts.URL}, "test-ref")
	if err != nil || !ok || out.Ref != "test-ref" {
		t.Errorf("get internal error: %v %v %v", out, ok, err)
	}

	// A member with no reachable URL is an error, not a silent miss.
	if _, _, err := c.getRecoveryBlobFromMember(context.Background(), Member{}, "test-ref"); err == nil {
		t.Errorf("expected error for member without URLs")
	}
}

func TestDoRecoveryHTTPRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(RecoveryBlob{Ref: "test-ref"})
	}))
	defer ts.Close()

	ctx := context.Background()

	var out RecoveryBlob
	err := doRecoveryHTTPRequest(ctx, ts.Client(), ts.URL, http.MethodGet, "test-token", nil, &out)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if out.Ref != "test-ref" {
		t.Errorf("unexpected blob ref: %s", out.Ref)
	}

	// auth fail
	if err := doRecoveryHTTPRequest(ctx, ts.Client(), ts.URL, http.MethodGet, "bad-token", nil, &out); err == nil {
		t.Errorf("expected error")
	}

	// transport fail (bad url)
	if err := doRecoveryHTTPRequest(ctx, ts.Client(), "http://127.0.0.1:0", http.MethodGet, "", nil, nil); err == nil {
		t.Errorf("expected error")
	}
}
