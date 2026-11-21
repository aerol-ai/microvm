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
// before. A Containers.Delete drops the ID's entry, and a check that began
// before any delete does not put its answer in after it, so an entry never
// outlives a delete of its container. None of that is needed for a right
// answer (the bytes decide a hit); it keeps memory to the containers that
// exist.
type specMemo struct {
	policy     rootpolicy.Policy
	maxEntries int
	maxBytes   int

	mu    sync.Mutex
	byID  map[string]*list.Element
	order *list.List // of *memoEntry, most recently used first
	// drops counts deletes. A check notes it when it misses and puts its
	// answer in only if no delete came in between.
	drops uint64
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
		byID: map[string]*list.Element{}, order: list.New()}
}

// check is a rootpolicy.SpecCheck: rootpolicy.CheckSpecFacts with the
// memo's policy, answered from the memo when id's entry was made from
// these exact bytes.
func (m *specMemo) check(id string, raw []byte) (*rootpolicy.SpecFacts, error) {
	sum := sha256.Sum256(raw)
	facts, drops := m.get(id, sum)
	if facts != nil {
		return facts, nil
	}
	facts, err := rootpolicy.CheckSpecFacts(m.policy, id, raw)
	if err != nil {
		return nil, err
	}
	m.put(id, sum, facts, drops)
	return facts, nil
}

// get returns id's facts when they were made from bytes with this sum, and
// the delete count a put of a new answer must still match.
func (m *specMemo) get(id string, sum [sha256.Size]byte) (*rootpolicy.SpecFacts, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.byID[id]
	if !ok || el.Value.(*memoEntry).sum != sum {
		return nil, m.drops
	}
	m.order.MoveToFront(el)
	return el.Value.(*memoEntry).facts, m.drops
}

func (m *specMemo) put(id string, sum [sha256.Size]byte, facts *rootpolicy.SpecFacts, drops uint64) {
	if len(id)+facts.Size() > m.maxBytes {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.drops != drops {
		return // a delete came in while this check ran
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

// drop forgets id's entry: its container is being deleted.
func (m *specMemo) drop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drops++
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
