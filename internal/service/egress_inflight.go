package service

import (
	"net/netip"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
)

// egressInflightMaxAge bounds how long an attach that never settled (its
// create or start died without a detach) stays in full syncs. Creates and
// starts finish well inside it.
const egressInflightMaxAge = 15 * time.Minute

// egressInflight is the set of sandboxes attached to the gateway whose store
// row doesn't show it yet: a create's attach runs alongside its row persist
// (latency amendment §8.2), and a start attaches before it writes the row.
// A full Sync is built from the store, so without these it would detach a
// sandbox whose Attach just succeeded and whose driver block was lifted,
// leaving it unfiltered (review finding 1).
type egressInflight struct {
	mu sync.Mutex
	m  map[string]inflightSpec
}

type inflightSpec struct {
	spec egress.Spec
	at   time.Time
}

func (f *egressInflight) put(spec egress.Spec) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]inflightSpec{}
	}
	f.m[spec.ID] = inflightSpec{spec: spec, at: time.Now()}
}

func (f *egressInflight) drop(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, id)
}

func (f *egressInflight) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.m)
}

// merge adds the in-flight attaches to a full Sync's specs. started maps each
// started store row to its IP: a row that shows the sandbox started on the
// same IP is authoritative (the store is written before a live policy
// change is applied), so its entry is dropped. Entries older than
// egressInflightMaxAge are dropped too.
func (f *egressInflight) merge(specs []egress.Spec, started map[string]netip.Addr, now time.Time) []egress.Spec {
	f.mu.Lock()
	defer f.mu.Unlock()
	have := make(map[string]bool, len(specs))
	for _, s := range specs {
		have[s.ID] = true
	}
	for id, in := range f.m {
		if ip, ok := started[id]; (ok && ip == in.spec.IP) || now.Sub(in.at) > egressInflightMaxAge {
			delete(f.m, id)
			continue
		}
		if !have[id] {
			specs = append(specs, in.spec)
		}
	}
	return specs
}
