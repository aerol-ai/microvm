package service

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// blockingPlacementCluster lets a test hold the placement batch open and act
// on the holder map while the RPC is "in flight" — the window a create lands
// in on a busy worker.
type blockingPlacementCluster struct {
	*cluster.Noop
	mu         sync.Mutex
	placements map[string]cluster.Placement
	members    []cluster.Member
	batchIDs   [][]string

	inFlight chan struct{} // closed once the batch has been entered
	release  chan struct{} // test closes this to let the batch return
	blocked  bool
}

func newBlockingPlacementCluster(self string) *blockingPlacementCluster {
	return &blockingPlacementCluster{
		Noop:       cluster.NewNoop(self, "http://"+self, ""),
		placements: map[string]cluster.Placement{},
		inFlight:   make(chan struct{}),
		release:    make(chan struct{}),
	}
}

func (c *blockingPlacementCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	c.mu.Lock()
	c.batchIDs = append(c.batchIDs, append([]string(nil), ids...))
	blocked := c.blocked
	c.blocked = false
	snapshot := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			snapshot[id] = p
		}
	}
	c.mu.Unlock()
	if blocked {
		close(c.inFlight)
		<-c.release
	}
	return snapshot
}

func (c *blockingPlacementCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *blockingPlacementCluster) LocalMembers() []cluster.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cluster.Member(nil), c.members...)
}

func (c *blockingPlacementCluster) Members() []cluster.Member { return c.LocalMembers() }

func (c *blockingPlacementCluster) batches() [][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]string, len(c.batchIDs))
	copy(out, c.batchIDs)
	return out
}

// A create that finishes while the placement batch is in flight adds a holder
// entry the batch was never asked about. Judging that entry against the older
// response deleted it — discarding confirmed ACKs and the repair targets the
// next maintenance pass would have used.
func TestSecretHolderRefreshKeepsHolderCreatedDuringPlacementBatch(t *testing.T) {
	const (
		existingID = "sb-existing"
		newID      = "sb-created-mid-batch"
	)
	cl := newBlockingPlacementCluster("node-a")
	cl.blocked = true
	cl.members = []cluster.Member{
		{NodeID: "node-a", Alive: true},
		{NodeID: "node-b", Alive: true},
		{NodeID: "node-c", Alive: true},
	}
	for _, id := range []string{existingID, newID} {
		cl.placements[id] = cluster.Placement{
			SandboxID: id, OwnerNodeID: "node-a", IncarnationID: "inc-" + id,
			SecretSealGeneration: 1, State: cluster.PlacementStatePlaced,
			SecretRecipients: []string{"node-a", "node-b", "node-c"},
		}
		t.Cleanup(func() { clearSecretFanoutHolders(id) })
	}
	clearSecretFanoutHolders(existingID)
	clearSecretFanoutHolders(newID)
	resetSecretHoldersForGeneration(existingID, "inc-"+existingID, 1, "node-a", "node-b", "node-c")

	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cluster:              cl,
		testSecretPeerPusher: &fakePeerPusher{},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.refreshSecretHolderPossession(context.Background())
	}()

	<-cl.inFlight
	// The create lands now: its holder state is live and confirmed.
	resetSecretHoldersForGeneration(newID, "inc-"+newID, 1, "node-a", "node-b", "node-c")
	close(cl.release)
	<-done

	if _, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: newID, incarnationID: "inc-" + newID}); !ok {
		t.Fatal("holder state created during the placement batch was deleted; its absence from an earlier response is not proof of deletion")
	}
	for _, batch := range cl.batches() {
		for _, id := range batch {
			if id == newID {
				t.Fatal("placement batch asked about a sandbox that did not exist when the page was captured")
			}
		}
	}
}

// An incarnation replacement under the same sandbox id must not be retired by
// a verdict reached against the earlier incarnation's snapshot.
func TestSecretHolderRefreshKeepsReplacementIncarnation(t *testing.T) {
	const sandboxID = "sb-replaced"
	cl := newBlockingPlacementCluster("node-a")
	cl.blocked = true
	cl.members = []cluster.Member{{NodeID: "node-a", Alive: true}, {NodeID: "node-b", Alive: true}, {NodeID: "node-c", Alive: true}}
	// The authoritative view already moved on to inc-2; the captured entry is
	// for inc-1 and is legitimately retired.
	cl.placements[sandboxID] = cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: "inc-2",
		SecretSealGeneration: 1, State: cluster.PlacementStatePlaced,
		SecretRecipients: []string{"node-a", "node-b", "node-c"},
	}
	t.Cleanup(func() { clearSecretFanoutHolders(sandboxID) })
	clearSecretFanoutHolders(sandboxID)
	resetSecretHoldersForGeneration(sandboxID, "inc-1", 1, "node-a", "node-b", "node-c")

	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cluster:              cl,
		testSecretPeerPusher: &fakePeerPusher{},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.refreshSecretHolderPossession(context.Background())
	}()
	<-cl.inFlight
	resetSecretHoldersForGeneration(sandboxID, "inc-2", 1, "node-a", "node-b", "node-c")
	close(cl.release)
	<-done

	if _, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: sandboxID, incarnationID: "inc-2"}); !ok {
		t.Fatal("replacement incarnation retired by a verdict about the previous incarnation")
	}
	if _, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: sandboxID, incarnationID: "inc-1"}); ok {
		t.Fatal("superseded incarnation survived; the captured entry should have been retired")
	}
}

// limitedBatchCluster enforces the real endpoint limit: a request carrying more
// ids than the handler accepts fails, and the agent's failure result is nil
// ("not authoritative"), which makes the whole tick skip.
type limitedBatchCluster struct {
	*cluster.Noop
	mu         sync.Mutex
	placements map[string]cluster.Placement
	members    []cluster.Member
	batchSizes []int
	rejected   int
}

func (c *limitedBatchCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batchSizes = append(c.batchSizes, len(ids))
	if len(ids) > cluster.MaxPlacementPageLimit {
		c.rejected++
		return nil
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out
}

func (c *limitedBatchCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(ids) > cluster.MaxPlacementPageLimit {
		return nil, fmt.Errorf("too many placement ids: %d", len(ids))
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *limitedBatchCluster) LocalMembers() []cluster.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cluster.Member(nil), c.members...)
}

func (c *limitedBatchCluster) Members() []cluster.Member { return c.LocalMembers() }

// A node holding more entries than the batch endpoint accepts must keep
// refreshing them, a page at a time, instead of failing the request and
// skipping every probe for as long as the skew lasts.
func TestSecretHolderRefreshPagesPastEndpointLimit(t *testing.T) {
	const holders = cluster.MaxPlacementPageLimit + 1
	cl := &limitedBatchCluster{
		Noop:       cluster.NewNoop("node-a", "http://node-a", ""),
		placements: make(map[string]cluster.Placement, holders),
		members: []cluster.Member{
			{NodeID: "node-a", Alive: true},
			{NodeID: "node-b", Alive: true},
			{NodeID: "node-c", Alive: true},
		},
	}
	stale := time.Now().Add(-secretHolderACKTTL)
	for i := range holders {
		id := fmt.Sprintf("sb-%05d", i)
		cl.placements[id] = cluster.Placement{
			SandboxID: id, OwnerNodeID: "node-a", IncarnationID: "inc-" + id,
			SecretSealGeneration: 1, State: cluster.PlacementStatePlaced,
			SecretRecipients: []string{"node-a", "node-b", "node-c"},
		}
		resetSecretHoldersForGeneration(id, "inc-"+id, 1, "node-a", "node-b", "node-c")
		// Age the ACKs so every holder is due for a probe.
		if v, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: id, incarnationID: "inc-" + id}); ok {
			hs := v.(*holderNodeSet)
			hs.mu.Lock()
			for node := range hs.nodes {
				hs.nodes[node] = stale
			}
			hs.mu.Unlock()
		}
	}
	t.Cleanup(func() {
		for i := range holders {
			clearSecretFanoutHolders(fmt.Sprintf("sb-%05d", i))
		}
	})

	pusher := &fakePeerPusher{probeStrict: true, probeHolding: []string{"node-b", "node-c"}}
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cluster:              cl,
		testSecretPeerPusher: pusher,
	}

	probedFirst := map[string]struct{}{}
	svc.refreshSecretHolderPossession(context.Background())
	pusher.mu.Lock()
	for id := range pusher.probeByID {
		probedFirst[id] = struct{}{}
	}
	pusher.mu.Unlock()

	cl.mu.Lock()
	rejected, sizes := cl.rejected, append([]int(nil), cl.batchSizes...)
	cl.mu.Unlock()
	if rejected != 0 {
		t.Fatalf("placement batch rejected %d times; a node with %d holders must page within the endpoint limit", rejected, holders)
	}
	for _, size := range sizes {
		if size > cluster.MaxPlacementPageLimit {
			t.Fatalf("submitted %d ids in one batch, endpoint accepts at most %d", size, cluster.MaxPlacementPageLimit)
		}
	}
	if len(probedFirst) == 0 {
		t.Fatal("first refresh probed nothing; oversized holder maps must still make progress")
	}

	// The cursor must move on, so the holders the first page could not reach
	// are not starved forever.
	svc.refreshSecretHolderPossession(context.Background())
	fresh := 0
	pusher.mu.Lock()
	for id := range pusher.probeByID {
		if _, seen := probedFirst[id]; !seen {
			fresh++
		}
	}
	pusher.mu.Unlock()
	if fresh == 0 {
		t.Fatal("second refresh revisited only the first page; the fair cursor did not advance")
	}
}

// The page walks every entry in stable order and wraps around, so a map larger
// than one page is covered across ticks.
func TestSecretHolderPageWrapsWithCursor(t *testing.T) {
	ids := []string{"sb-1", "sb-2", "sb-3", "sb-4", "sb-5"}
	for _, id := range ids {
		resetSecretHoldersForGeneration(id, "inc", 1, "node-a")
	}
	t.Cleanup(func() {
		for _, id := range ids {
			clearSecretFanoutHolders(id)
		}
	})

	seen := map[string]int{}
	cursor := ""
	for range len(ids) {
		page, next, total := secretHolderPage(cursor, 2)
		if total != len(ids) {
			t.Fatalf("total = %d, want %d", total, len(ids))
		}
		if len(page) != 2 {
			t.Fatalf("page size = %d, want 2", len(page))
		}
		for _, e := range page {
			seen[e.key.sandboxID]++
		}
		cursor = next
	}
	for _, id := range ids {
		if seen[id] == 0 {
			t.Fatalf("%s never visited across %d pages of 2", id, len(ids))
		}
	}
}
