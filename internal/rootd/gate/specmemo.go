package gate

import (
	"container/list"
	"crypto/sha256"
	"sync"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// specMemo keeps the answer to a spec check a create has already paid for.
//
// A create sends the container's spec to Containers.Create, and the gate
// checks it there; at Tasks.Create the gate reads the stored container
// back from containerd and checks it again, since a container stored
// before the gate, or under a wider policy, must not start through it.
// Decoding the spec (the seccomp profile alone is most of it) was most of
// the gate's work on a create. rootpolicy.CheckSpecFacts is a pure function
// of the policy, the container ID and the spec's bytes, so its answer for
// the same three is the same answer. The memo keeps it per container ID,
// under the SHA-256 of the exact bytes it was decoded from. A lookup with
// any other bytes misses, and the bytes are decoded and checked in full. A
// SHA-256 collision is as hard to find as one in containerd's own content
// store, which names every image layer by that hash.
//
// Only what the bytes say is kept. Everything that can change on disk (a
// bind source, a runsc config, the network namespace, a stdio FIFO) is
// checked again at each call, as before; so is every other field of the
// container record.
//
// It is bounded three ways, because a broken agent can send what it likes:
//   - one entry per container ID, so new specs under one ID replace each
//     other;
//   - at most maxEntries IDs, the least recently used going first;
//   - no entry for a spec whose facts are bigger than maxBytes (a spec
//     may bind in as many paths as fit in a message): those are decoded at
//     each check.
//
// Only passes are kept; a refused spec is decoded again each time, as
// before. A Containers.Delete drops the ID's entry twice: when the gate
// checks the delete, and again once containerd has answered it, since a
// Tasks.Create checked in between still reads the stored container. Each
// drop starts a new generation for that ID, and a check of the ID that was
// decoding across a drop keeps its answer out. So once a delete the gate
// forwarded has ended, the memo holds nothing for that container until a
// later check reads it from containerd again. A delete touches only its own
// ID: deleting other containers, or ones that do not exist, keeps no other
// check's answer out. None of this is needed for a right answer (the bytes
// decide a hit); it keeps memory to the containers that exist.
type specMemo struct {
	policy     rootpolicy.Policy
	maxEntries int
	maxBytes   int

	mu    sync.Mutex
	byID  map[string]*list.Element
	order *list.List // of *memoEntry, most recently used first
	// inflight holds, per ID, the checks of it that missed and are
	// decoding, and the generation they started in. An entry lives only
	// while such a check runs, so there are never more than calls in
	// flight.
	inflight map[string]*pending
	// gens numbers generations; none is used twice.
	gens uint64
}

type pending struct {
	gen     uint64
	running int
}

type memoEntry struct {
	id    string
	sum   [sha256.Size]byte
	facts *rootpolicy.SpecFacts
}

const (
	// memoEntries covers the creates in flight at once on a node (the
	// agent's containerd connection holds at most 1024 calls open,
	// rootd.maxStreams) and the task starts that follow them. A miss costs
	// one decode, never a wrong answer.
	memoEntries = 1024
	// memoEntryBytes is far above the agent's specs, which bind in a few
	// paths (the toolbox, the helper's files, external mounts). With
	// memoEntries it bounds the memo at a few MiB.
	memoEntryBytes = 4096
)

func newSpecMemo(p rootpolicy.Policy, maxEntries, maxBytes int) *specMemo {
	return &specMemo{policy: p, maxEntries: maxEntries, maxBytes: maxBytes,
		byID: map[string]*list.Element{}, order: list.New(), inflight: map[string]*pending{}}
}

// check is a rootpolicy.SpecCheck: rootpolicy.CheckSpecFacts with the
// memo's policy, answered from the memo when id's entry was made from
// these exact bytes.
func (m *specMemo) check(id string, raw []byte) (*rootpolicy.SpecFacts, error) {
	sum := sha256.Sum256(raw)
	facts, gen := m.get(id, sum)
	if facts != nil {
		return facts, nil
	}
	facts, err := rootpolicy.CheckSpecFacts(m.policy, id, raw)
	if err != nil {
		m.abandon(id)
		return nil, err
	}
	m.put(id, sum, facts, gen)
	return facts, nil
}

// get returns id's facts when they were made from bytes with this sum. On
// a miss it counts the caller as decoding id, and returns the generation a
// put of its answer must still match. A miss must end in put or abandon.
func (m *specMemo) get(id string, sum [sha256.Size]byte) (*rootpolicy.SpecFacts, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.byID[id]; ok && el.Value.(*memoEntry).sum == sum {
		m.order.MoveToFront(el)
		return el.Value.(*memoEntry).facts, 0
	}
	p := m.inflight[id]
	if p == nil {
		m.gens++
		p = &pending{gen: m.gens}
		m.inflight[id] = p
	}
	p.running++
	return nil, p.gen
}

// done ends a check of id that missed, and says whether no delete of id
// came in while it ran. The caller holds mu.
func (m *specMemo) done(id string, gen uint64) bool {
	p := m.inflight[id]
	if p == nil {
		return false
	}
	if p.running--; p.running == 0 {
		delete(m.inflight, id)
	}
	return p.gen == gen
}

// abandon ends a check of id that missed and has nothing to keep.
func (m *specMemo) abandon(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.done(id, 0)
}

// put ends a check of id that missed, keeping its answer unless a delete
// of id came in while it ran.
func (m *specMemo) put(id string, sum [sha256.Size]byte, facts *rootpolicy.SpecFacts, gen uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.done(id, gen) || len(id)+facts.Size() > m.maxBytes {
		return
	}
	if el, ok := m.byID[id]; ok {
		e := el.Value.(*memoEntry)
		e.sum, e.facts = sum, facts
		m.order.MoveToFront(el)
		return
	}
	m.byID[id] = m.order.PushFront(&memoEntry{id: id, sum: sum, facts: facts})
	for m.order.Len() > m.maxEntries {
		oldest := m.order.Back()
		m.order.Remove(oldest)
		delete(m.byID, oldest.Value.(*memoEntry).id)
	}
}

// drop forgets id's entry, and starts a new generation for the checks of
// id now decoding: its container is being, or has been, deleted.
func (m *specMemo) drop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.inflight[id]; p != nil {
		m.gens++
		p.gen = m.gens
	}
	if el, ok := m.byID[id]; ok {
		m.order.Remove(el)
		delete(m.byID, id)
	}
}

// entries is how many entries the memo holds.
func (m *specMemo) entries() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.order.Len()
}
