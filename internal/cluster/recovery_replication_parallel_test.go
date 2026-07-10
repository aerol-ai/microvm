package cluster

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplicateBlobToMembersAttemptsAllMembers(t *testing.T) {
	members := []Member{{NodeID: "a"}, {NodeID: "b"}, {NodeID: "c"}}
	var mu sync.Mutex
	called := map[string]int{}
	put := func(_ context.Context, m Member, _ RecoveryBlob) error {
		mu.Lock()
		defer mu.Unlock()
		called[m.NodeID]++
		if m.NodeID == "b" {
			return errors.New("b down")
		}
		return nil
	}
	err := replicateBlobToMembers(context.Background(), members, RecoveryBlob{Ref: "r"}, put)
	if err == nil || err.Error() != "b down" {
		t.Fatalf("expected b's error, got %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if called[id] != 1 {
			t.Errorf("member %s called %d times, want 1", id, called[id])
		}
	}
}

func TestReplicateBlobToMembersFirstErrorInMemberOrder(t *testing.T) {
	// The old serial loop returned the first error in member order. Two
	// members fail here, with the earlier one finishing LAST, to prove the
	// concurrent version still picks by member order, not completion order.
	members := []Member{{NodeID: "a"}, {NodeID: "b"}, {NodeID: "c"}}
	errA := errors.New("a failed")
	errC := errors.New("c failed")
	cDone := make(chan struct{})
	put := func(_ context.Context, m Member, _ RecoveryBlob) error {
		switch m.NodeID {
		case "a":
			<-cDone
			return errA
		case "c":
			defer close(cDone)
			return errC
		}
		return nil
	}
	err := replicateBlobToMembers(context.Background(), members, RecoveryBlob{}, put)
	if !errors.Is(err, errA) {
		t.Fatalf("expected first member's error %v, got %v", errA, err)
	}
}

func TestReplicateBlobToMembersRunsConcurrently(t *testing.T) {
	// Each put blocks until every put has started. A serial implementation
	// never gets past the first member and the watchdog fails the test.
	const n = 4
	members := make([]Member, n)
	for i := range members {
		members[i] = Member{NodeID: string(rune('a' + i))}
	}
	started := make(chan struct{}, n)
	release := make(chan struct{})
	put := func(_ context.Context, _ Member, _ RecoveryBlob) error {
		started <- struct{}{}
		<-release
		return nil
	}
	go func() {
		deadline := time.After(5 * time.Second)
		for i := 0; i < n; i++ {
			select {
			case <-started:
			case <-deadline:
				t.Error("puts did not all start concurrently; replication appears serial")
				close(release)
				return
			}
		}
		close(release)
	}()
	if err := replicateBlobToMembers(context.Background(), members, RecoveryBlob{}, put); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReplicateBlobToMembersEdgeCases(t *testing.T) {
	var calls atomic.Int32
	put := func(_ context.Context, _ Member, _ RecoveryBlob) error {
		calls.Add(1)
		return nil
	}
	if err := replicateBlobToMembers(context.Background(), nil, RecoveryBlob{}, put); err != nil {
		t.Fatalf("no members: unexpected error %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("no members: put called %d times", calls.Load())
	}
	if err := replicateBlobToMembers(context.Background(), []Member{{NodeID: "a"}}, RecoveryBlob{}, put); err != nil {
		t.Fatalf("single member: unexpected error %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("single member: put called %d times, want 1", calls.Load())
	}
}

func TestStoreAndReplicateRecoveryBlobFansOutToAllPeers(t *testing.T) {
	// End-to-end: the blob must land on every remote control-plane peer,
	// skipping self, via real HTTP PUTs.
	var hits atomic.Int32
	newPeer := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut {
				t.Errorf("unexpected method %s", r.Method)
			}
			hits.Add(1)
			w.WriteHeader(http.StatusCreated)
		}))
	}
	peer1 := newPeer()
	defer peer1.Close()
	peer2 := newPeer()
	defer peer2.Close()

	fsm := newPlacementFSM()
	fsm.recoveryStore = newPlacementRecoveryMemoryStore()
	c := &Cluster{
		nodeID: "self",
		fsm:    fsm,
		gossip: &gossipNode{
			memberIndex: &gossipMemberIndex{
				members: map[string]Member{
					"self":  {NodeID: "self", Alive: true, Role: "server", APIURL: "http://ignored"},
					"node2": {NodeID: "node2", Alive: true, Role: "server", APIURL: peer1.URL},
					"node3": {NodeID: "node3", Alive: true, Role: "server", APIURL: peer2.URL},
				},
			},
		},
		httpClient: http.DefaultClient,
	}

	blob, err := newRecoveryBlob("sb1", placementRecovery{})
	if err != nil {
		t.Fatalf("newRecoveryBlob: %v", err)
	}
	if err := c.storeAndReplicateRecoveryBlob(context.Background(), blob); err != nil {
		t.Fatalf("storeAndReplicateRecoveryBlob: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected 2 peer PUTs, got %d", hits.Load())
	}
	if _, ok, err := c.RecoveryBlob(context.Background(), blob.Ref); err != nil || !ok {
		t.Fatalf("blob not stored locally: ok=%v err=%v", ok, err)
	}
}
