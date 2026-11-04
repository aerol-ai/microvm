package service

import (
	"strings"
	"sync"
)

// createsInFlight counts the creates running for each sandbox ID. A create's
// runtime instance exists before its row does: the driver brings the
// container (or VM, WASM worker, isolate) up, and only then is the row
// written. Reconcile's orphan sweep lists the runtime after reading the rows,
// so an instance whose create is still running has no row in its snapshot and
// looks exactly like a leak; destroying it kills the create mid-flight
// ("cannot start a container that has stopped"). The sweep skips an ID with a
// create running, and rechecks the row of any other before destroying it. The
// zombie-route sweep has the same blind spot for the route a create installs
// before its row (ownsRoute).
//
// It is counted, not a set: two concurrent creates of one ID (an idempotent
// create-with-id retry) both hold it until both return.
type createsInFlight struct {
	mu sync.Mutex
	n  map[string]int
}

// begin marks a create of id as running until the returned func is called.
// A create calls it before its runtime create and defers the release, which
// then runs after the row is written or the rollback has removed the
// instance.
func (c *createsInFlight) begin(id string) func() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int{}
	}
	c.n[id]++
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.n[id]--; c.n[id] <= 0 {
				delete(c.n, id)
			}
		})
	}
}

// ownsRoute reports whether a Caddy route @id belongs to a sandbox whose
// create is running: every per-sandbox route is "sandbox-<id>" or starts
// "sandbox-<id>-", and a create installs its public route before it writes
// its row, so the zombie-route sweep would otherwise delete it.
func (c *createsInFlight) ownsRoute(routeID string) bool {
	rest, ok := strings.CutPrefix(routeID, "sandbox-")
	if !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.n {
		if after, ok := strings.CutPrefix(rest, id); ok && (after == "" || after[0] == '-') {
			return true
		}
	}
	return false
}

// running reports whether a create of id is running.
func (c *createsInFlight) running(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[id] > 0
}
