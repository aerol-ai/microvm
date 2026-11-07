package cluster

import (
	"sync"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

// unreportedLoad is load the FSM no longer counts as pending on a node but
// that the node's capacity heartbeat may not show yet (plan item C7, I4).
//
// Two writes take load out of the FSM's pending-reservation sums before the
// owner's next heartbeat can show it: opPlace promoting a reservation, and a
// failover opReassign handing a placed sandbox to a new owner. Until that
// heartbeat arrived the load counted nowhere, so placement and the leader's
// reservation admission handed the same room out twice. The worker's own
// admitter refused the overflow, which kept the node within budget, but a
// create another node had room for failed with a 503.
//
// It is per server and never replicated. The FSM records into it while it
// applies an entry, and every server applies every entry, so a follower that
// routes creates and a newly elected leader hold the same load the old leader
// did, with no handoff. Recording never feeds back into replicated state, so
// FSM apply stays a function of the log alone.
//
// Entries are ordered by a counter, not a clock. A heartbeat clears exactly
// the entries recorded before its request was sent: a worker admits a sandbox
// before it proposes the promote, so a snapshot requested after this server
// applied the promote must include it, while one requested earlier may not,
// however long either answer takes and whatever the clocks say.
//
// mu is a leaf lock: nothing is called while it is held. The FSM records
// under its own lock, so this must never wait on anything that could wait on
// the FSM.
type unreportedLoad struct {
	mu    sync.RWMutex
	seq   uint64
	nodes map[string]*unreportedNodeLoad
}

type unreportedNodeLoad struct {
	// entries are in recording order, so a heartbeat drops a prefix.
	entries []unreportedEntry
	// sum and runtimes are the entries totalled in that order, so a lookup
	// is one map read, not one per sandbox. runtimes is replaced, never
	// written in place: load hands it out after the lock is released.
	sum      capacity.Request
	runtimes map[string]int
}

// unreportedEntry keeps only what placement counts. A full capacity.Request
// also carries labels and artifact ids that no budget check reads.
type unreportedEntry struct {
	seq      uint64
	cpu      float64
	memoryMB int
	diskGB   int
	gpus     int
	runtime  string
}

func newUnreportedLoad() *unreportedLoad {
	return &unreportedLoad{nodes: make(map[string]*unreportedNodeLoad)}
}

// record adds req to nodeID's unreported load.
func (u *unreportedLoad) record(nodeID string, req capacity.Request) {
	if u == nil || nodeID == "" {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.nodes == nil {
		u.nodes = make(map[string]*unreportedNodeLoad)
	}
	u.seq++
	n := u.nodes[nodeID]
	if n == nil {
		n = &unreportedNodeLoad{}
		u.nodes[nodeID] = n
	}
	e := unreportedEntry{seq: u.seq, cpu: req.CPU, memoryMB: req.MemoryMB, diskGB: req.DiskGB, gpus: req.GPUs, runtime: req.Runtime}
	n.entries = append(n.entries, e)
	n.sum.CPU += e.cpu
	n.sum.MemoryMB += e.memoryMB
	n.sum.DiskGB += e.diskGB
	n.sum.GPUs += e.gpus
	runtimes := make(map[string]int, len(n.runtimes)+1)
	for rt, count := range n.runtimes {
		runtimes[rt] = count
	}
	runtimes[e.runtime]++
	n.runtimes = runtimes
}

// mark is the position a heartbeat requested now is measured against. Take
// it BEFORE sending the request (or reading the local admitter): an entry
// recorded after it may be missing from the answer.
func (u *unreportedLoad) mark() uint64 {
	if u == nil {
		return 0
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.seq
}

// reported drops nodeID's entries recorded at or before mark. A heartbeat
// requested after them counts those sandboxes itself; keeping them too would
// count the same room twice.
func (u *unreportedLoad) reported(nodeID string, mark uint64) {
	if u == nil || nodeID == "" {
		return
	}
	// Our own lease is re-read on every placement call, and usually finds
	// nothing to clear. Checking under the read lock first keeps those
	// calls from queueing behind each other on the write lock, and from
	// stalling the per-node lookups other creates are making.
	u.mu.RLock()
	n := u.nodes[nodeID]
	covered := n != nil && n.entries[0].seq <= mark
	u.mu.RUnlock()
	if !covered {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	// Re-read: another heartbeat may have cleared this node meanwhile.
	n = u.nodes[nodeID]
	i := 0
	for n != nil && i < len(n.entries) && n.entries[i].seq <= mark {
		i++
	}
	if i == 0 {
		return
	}
	if i == len(n.entries) {
		delete(u.nodes, nodeID)
		return
	}
	// Re-total rather than subtract: float CPU drifts under add-then-
	// subtract, and a sum a hair above the truth refuses a create that
	// exactly fits.
	n.entries = n.entries[i:]
	n.sum = capacity.Request{}
	runtimes := make(map[string]int, len(n.runtimes))
	for _, e := range n.entries {
		n.sum.CPU += e.cpu
		n.sum.MemoryMB += e.memoryMB
		n.sum.DiskGB += e.diskGB
		n.sum.GPUs += e.gpus
		runtimes[e.runtime]++
	}
	n.runtimes = runtimes
}

// retain drops nodes no longer in the membership view, except keep (this
// server, which is never in a peer sweep). A departed node sends no more
// heartbeats, so without this its entries would stay for the life of the
// process.
func (u *unreportedLoad) retain(live map[string]struct{}, keep string) {
	if u == nil || len(live) == 0 {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for id := range u.nodes {
		if id == keep {
			continue
		}
		if _, ok := live[id]; !ok {
			delete(u.nodes, id)
		}
	}
}

// load returns nodeID's unreported load. The runtime map is shared and must
// not be modified.
func (u *unreportedLoad) load(nodeID string) (capacity.Request, map[string]int, bool) {
	if u == nil {
		return capacity.Request{}, nil, false
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	n := u.nodes[nodeID]
	if n == nil {
		return capacity.Request{}, nil, false
	}
	return n.sum, n.runtimes, true
}

// pendingLoad is what placement adds to each node's last capacity heartbeat:
// reservations still in flight (the FSM) and load the FSM stopped counting
// that the heartbeat does not show yet.
//
// Nodes are looked up one at a time, where placement reads them. Merging the
// unreported load into the FSM's maps up front cost every create a map entry
// and a runtime map per node holding any: 1.3 ms and 2 MB per read at 400
// creates/s on 2,000 nodes, against 20 µs without it.
type pendingLoad struct {
	reserved   map[string]capacity.Request
	runtimes   map[string]map[string]int
	unreported *unreportedLoad
}

// of returns nodeID's pending load and its per-runtime create counts. The
// runtime map may be shared and must not be modified.
func (p pendingLoad) of(nodeID string) (capacity.Request, map[string]int) {
	req := p.reserved[nodeID]
	byRuntime := p.runtimes[nodeID]
	sum, unreported, ok := p.unreported.load(nodeID)
	if !ok {
		return req, byRuntime
	}
	req.CPU += sum.CPU
	req.MemoryMB += sum.MemoryMB
	req.DiskGB += sum.DiskGB
	req.GPUs += sum.GPUs
	if len(byRuntime) == 0 {
		return req, unreported
	}
	merged := make(map[string]int, len(byRuntime)+len(unreported))
	for rt, count := range byRuntime {
		merged[rt] = count
	}
	for rt, count := range unreported {
		merged[rt] += count
	}
	return req, merged
}
