package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Every write that can open a port reads the port's gate when it writes,
// never from an older copy (A2; review 2 of the token-gated ports).
//
// A port's visibility lives in its exposed_ports row, and only expose and
// unexpose change it (under lockExposedPort). Every other writer works from a
// sandbox row it read earlier: start, reconcile (which walks every sandbox),
// runtime start events, the serverless stop and wake paths, lifecycle flips,
// failover replay. If that copy is from before a change to "token", acting on
// it would put back a way around the ingress proxy's token check: the direct
// port route, or the port's entry on toolboxd's /proxy allowlist. The Caddy
// coalescer orders writes per (sandbox, port) but cannot tell an old intent
// from a new one.
//
// So each way in is written under one lock that all of its writers share,
// from state read from the store inside that lock:
//
//	way in            lock (all writers)           read inside the lock
//	port route        httpRouteLocks (id, port)    GetPort
//	/proxy allowlist  allowlistLocks (id)          ListPorts
//
// Why that is enough. expose raises a gate in this order: store the row, then
// write the route, then push the allowlist. A writer that read before the row
// was stored finishes its write before expose's own write can start (same
// lock), so expose's write is the last one. A writer that read after it sees
// the gate.
//
// Node-local locks and reads are enough in a cluster too: the v1 routes
// forward expose and unexpose calls to the owner, and start,
// reconcile, runtime events and failover replay run on the owner, whose
// store holds the rows. Ingress nodes route to the owner, never to the app.

// keyedLocks is a set of mutexes keyed by K. A key has an entry only while a
// call holds or waits for it, so the map stays as small as the work in
// flight. The zero value is ready to use.
type keyedLocks[K comparable] struct {
	mu sync.Mutex
	m  map[K]*portLock
}

// lock takes k's mutex and returns its unlock.
func (l *keyedLocks[K]) lock(k K) func() {
	l.mu.Lock()
	if l.m == nil {
		l.m = make(map[K]*portLock)
	}
	e := l.m[k]
	if e == nil {
		e = &portLock{}
		l.m[k] = e
	}
	e.refs++
	l.mu.Unlock()
	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		l.mu.Lock()
		if e.refs--; e.refs == 0 {
			delete(l.m, k)
		}
		l.mu.Unlock()
	}
}

// refs is the number of calls holding or waiting for k's mutex, and keys
// the number of keys with any. Tests only.
func (l *keyedLocks[K]) refs(k K) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[k]; e != nil {
		return e.refs
	}
	return 0
}

func (l *keyedLocks[K]) keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

// Stages testAfterRouteGateRead reports.
const (
	gateReadPortRoute = "port-route"
	gateReadAllowlist = "allowlist"
)

func (s *Service) afterRouteGateRead(stage string) {
	if s.testAfterRouteGateRead != nil {
		s.testAfterRouteGateRead(stage)
	}
}

// portGatedNow reports whether sandbox's port is token-gated now. The stored
// row decides when there is one. With none, sandbox's copy decides: a first
// public expose writes its route before its row. A failed read is returned,
// not guessed, so the caller writes no route rather than maybe the open one.
// The caller holds httpRouteLocks for the port.
func (s *Service) portGatedNow(ctx context.Context, sandbox *models.Sandbox, port int) (bool, error) {
	if s.store == nil {
		return portTokenGated(sandbox, port), nil
	}
	row, err := s.store.GetPort(ctx, sandbox.ID, port)
	if err != nil {
		return false, fmt.Errorf("read the visibility of port %d before writing its route: %w", port, err)
	}
	if row == nil {
		return portTokenGated(sandbox, port), nil
	}
	return row.TokenGated(), nil
}

// toolboxProxyPorts is the /proxy allowlist for ports: every exposed port
// but the token-gated ones. toolboxd's /proxy/<port> path is served straight
// from the sandbox root route, around the ingress proxy's token check, so a
// gated port is never on it (A2).
func toolboxProxyPorts(ports []models.ExposedPort) []int {
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p.TokenGated() {
			continue
		}
		out = append(out, p.Port)
	}
	return out
}
