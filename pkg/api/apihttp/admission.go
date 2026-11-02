package apihttp

import (
	"cmp"
	"container/list"
	"context"
	"errors"
	"expvar"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// ErrOverloaded is load shedding: this node already runs as many requests of
// one expensive kind as it is configured to, the caller's tenant is within
// its share, and a short wait freed no slot. It is answered at once with 503
// and Retry-After (Classify) instead of being queued behind the others. On
// the bank flagship (2026-11-01) queued cluster lists reached a 37 s p99 and
// ended in 502s from a restarted node; a fast, retryable refusal keeps the
// node, and every request it is already serving, alive.
var ErrOverloaded = errors.New("this node is serving as many cluster list requests as it is configured to; retry shortly")

// ErrRateLimited is the per-tenant half of the same gate: the caller's own
// tenant already holds its share of the node's slots, and none of them freed
// within the queue wait. Answered 429 with Retry-After and code rate_limited
// (Classify), so the noisy tenant learns it is the one to slow down, while
// every other tenant keeps its own share of the node.
var ErrRateLimited = errors.New("your tenant is running as many cluster list requests on this node as its share allows; retry shortly")

// OverloadedRetryAfterSeconds is the Retry-After sent with ErrOverloaded. A
// slot frees as soon as one request in flight ends, usually well inside a
// second, so a short hint is enough; every SDK also backs off on its own.
const OverloadedRetryAfterSeconds = 1

// RateLimitedRetryAfterSeconds is the Retry-After sent with ErrRateLimited:
// the tenant's own slot frees as soon as one of its requests ends.
const RateLimitedRetryAfterSeconds = 1

// OperatorFlow is the flow of every unscoped caller: the operator PAT, a
// fleet-wide token or binding, and a call that carries no Access (internal).
// They all act for the operator and list under owner "", so they share one
// share of the node, like one tenant.
const OperatorFlow = "operator"

// FlowOf names the fairness flow a request belongs to: the tenant (owner)
// its credential acts for, never the credential itself, so a tenant that
// mints a hundred tokens still gets one share. A team token, an OIDC
// identity acting for a team and a managed account map to "owner:<owner
// ref>"; unscoped callers to OperatorFlow. The "owner:" prefix keeps a
// managed account literally named "operator" out of the operator's flow.
func FlowOf(ctx context.Context) string {
	access, ok := controlplane.AccessFromContext(ctx)
	if !ok || access.Fleet {
		return OperatorFlow
	}
	owner := strings.TrimSpace(access.Identity.OwnerRef)
	if owner == "" {
		return OperatorFlow
	}
	return "owner:" + owner
}

// GateMetrics are a Gate's counters and gauges. Any of them may be nil. None
// is labelled by tenant: a flow's name is in Snapshot (the operator-only
// /debug/vars), never in a metric, so the series count stays fixed however
// many tenants call.
type GateMetrics struct {
	InFlight    *expvar.Int // requests holding a slot now
	Admitted    *expvar.Int // requests that got a slot
	Shed        *expvar.Int // refused 503: the node was full, the flow within its share
	RateLimited *expvar.Int // refused 429: the flow already held its share
	Queued      *expvar.Int // requests waiting for a slot now
	Flows       *expvar.Int // flows (tenants) holding or waiting for a slot now
}

// Gate bounds how many requests of one expensive kind run at once on this
// node, and how many of them one flow (tenant, FlowOf) may hold.
//
// A request that finds a free slot within its flow's share takes it at once.
// Otherwise it queues in its flow's FIFO for at most the gate's queue wait.
// A freed slot goes to the flows with waiters in round-robin order, skipping
// a flow that already holds its share, so a tenant with 100 requests queued
// and one with 1 queued each get the next turn in step, not first-come
// first-served across everyone. A waiter that times out is refused with
// ErrRateLimited when its own flow holds its share (that tenant is the one
// to slow down), else with ErrOverloaded (the node is full).
//
// Refusals happen only after the queue wait, never at once (unless the wait
// is 0): a client that ignores Retry-After then costs at most two requests
// a second per connection, where an instant refusal would invite a tight
// retry loop that spends the node's CPU on refusals.
//
// Cost per decision is O(1), plus O(flows with waiters) when a release scans
// for the next eligible flow. State exists only for a flow with a request in
// flight or queued and is dropped the moment it has neither, so memory is
// bounded by the requests the server is already holding. A nil *Gate admits
// everything.
type Gate struct {
	limit   int
	perFlow int // == limit when no per-flow share is in force
	wait    time.Duration
	metrics GateMetrics

	mu       sync.Mutex
	inFlight int
	queued   int
	flows    map[string]*gateFlow
	ring     list.List     // *gateFlow with waiters, in turn order
	next     *list.Element // the flow whose turn is next; nil = ring.Front()
}

type gateFlow struct {
	key      string
	inFlight int
	waiters  list.List     // *gateWaiter, oldest first
	turn     *list.Element // its element in Gate.ring while it has waiters
	refused  int64         // refusals since this flow's state was created
}

type gateWaiter struct {
	ready   chan struct{} // closed when a release hands it a slot
	granted bool          // set with ready, under Gate.mu
	elem    *list.Element // in its flow's waiters while queued
}

// NewGate returns a gate of limit slots, of which one flow may hold at most
// perFlow. limit <= 0 means no gate (nil); perFlow <= 0 or >= limit means no
// per-flow share (any flow may take every slot), with round-robin turns
// across flows still in force.
func NewGate(limit, perFlow int, wait time.Duration, metrics GateMetrics) *Gate {
	if limit <= 0 {
		return nil
	}
	if perFlow <= 0 || perFlow > limit {
		perFlow = limit
	}
	if wait < 0 {
		wait = 0
	}
	return &Gate{limit: limit, perFlow: perFlow, wait: wait, metrics: metrics, flows: map[string]*gateFlow{}}
}

// Acquire takes a slot for the request's flow (FlowOf(ctx)).
func (g *Gate) Acquire(ctx context.Context) (release func(), err error) {
	return g.AcquireFlow(ctx, FlowOf(ctx))
}

// AcquireFlow takes a slot for flow. On success release must be called once
// (more is safe). It returns ErrRateLimited or ErrOverloaded when no slot
// freed for this flow within the queue wait, and ErrOverloaded wrapping the
// context's error when the caller left while waiting (not counted as a
// refusal: the writer answers it silently, for a client that is gone).
func (g *Gate) AcquireFlow(ctx context.Context, flow string) (release func(), err error) {
	if g == nil {
		return func() {}, nil
	}
	g.mu.Lock()
	f := g.flowLocked(flow)
	// Invariant (kept by dispatchLocked on every release): while the node
	// has a free slot, every flow with waiters holds its share. So a free
	// slot within this flow's share skips nobody who could have taken it.
	if g.inFlight < g.limit && f.inFlight < g.perFlow && f.waiters.Len() == 0 {
		g.grantLocked(f)
		g.mu.Unlock()
		return g.releaser(f), nil
	}
	if g.wait <= 0 {
		err := g.refuseLocked(f)
		g.dropIfIdleLocked(f)
		g.mu.Unlock()
		return nil, err
	}
	w := g.enqueueLocked(f)
	g.mu.Unlock()

	timer := time.NewTimer(g.wait)
	defer timer.Stop()
	select {
	case <-w.ready:
		return g.releaser(f), nil
	case <-timer.C:
		g.mu.Lock()
		defer g.mu.Unlock()
		if w.granted {
			// A release handed this waiter the slot as the timer fired.
			return g.releaser(f), nil
		}
		g.dequeueLocked(f, w)
		err := g.refuseLocked(f)
		g.dropIfIdleLocked(f)
		return nil, err
	case <-ctx.Done():
		if g.abandon(f, w) {
			g.releaser(f)()
		}
		return nil, fmt.Errorf("%w: %w", ErrOverloaded, ctx.Err())
	}
}

// abandon takes a waiter whose caller left out of its flow's queue. It
// reports true when a release had already granted it a slot, which the
// caller then owns and must release.
func (g *Gate) abandon(f *gateFlow, w *gateWaiter) (granted bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if w.granted {
		return true
	}
	g.dequeueLocked(f, w)
	g.dropIfIdleLocked(f)
	return false
}

// Limit is the number of slots; 0 for a nil gate.
func (g *Gate) Limit() int {
	if g == nil {
		return 0
	}
	return g.limit
}

// PerFlowLimit is how many slots one flow may hold (Limit when no share is
// in force); 0 for a nil gate.
func (g *Gate) PerFlowLimit() int {
	if g == nil {
		return 0
	}
	return g.perFlow
}

func (g *Gate) flowLocked(key string) *gateFlow {
	f, ok := g.flows[key]
	if !ok {
		f = &gateFlow{key: key}
		g.flows[key] = f
		setMetric(g.metrics.Flows, int64(len(g.flows)))
	}
	return f
}

// dropIfIdleLocked forgets a flow with nothing in flight and nothing queued.
// Nobody holds such a flow afterwards: a releaser exists only while its flow
// has a slot in flight, a waiter only while it is queued or granted.
func (g *Gate) dropIfIdleLocked(f *gateFlow) {
	if f.inFlight == 0 && f.waiters.Len() == 0 && g.flows[f.key] == f {
		delete(g.flows, f.key)
		setMetric(g.metrics.Flows, int64(len(g.flows)))
	}
}

func (g *Gate) grantLocked(f *gateFlow) {
	f.inFlight++
	g.inFlight++
	addMetric(g.metrics.Admitted, 1)
	addMetric(g.metrics.InFlight, 1)
}

func (g *Gate) refuseLocked(f *gateFlow) error {
	f.refused++
	if g.perFlow < g.limit && f.inFlight >= g.perFlow {
		addMetric(g.metrics.RateLimited, 1)
		return ErrRateLimited
	}
	addMetric(g.metrics.Shed, 1)
	return ErrOverloaded
}

func (g *Gate) enqueueLocked(f *gateFlow) *gateWaiter {
	w := &gateWaiter{ready: make(chan struct{})}
	w.elem = f.waiters.PushBack(w)
	if f.turn == nil {
		f.turn = g.ring.PushBack(f)
	}
	g.queued++
	addMetric(g.metrics.Queued, 1)
	return w
}

func (g *Gate) dequeueLocked(f *gateFlow, w *gateWaiter) {
	f.waiters.Remove(w.elem)
	g.queued--
	addMetric(g.metrics.Queued, -1)
	if f.waiters.Len() == 0 {
		g.leaveRingLocked(f)
	}
}

func (g *Gate) leaveRingLocked(f *gateFlow) {
	if g.next == f.turn {
		g.next = f.turn.Next()
	}
	g.ring.Remove(f.turn)
	f.turn = nil
}

// dispatchLocked hands free slots to waiters, one per turn, round-robin over
// the flows that have waiters and are below their share.
func (g *Gate) dispatchLocked() {
	for g.inFlight < g.limit && g.ring.Len() > 0 {
		e := g.next
		if e == nil {
			e = g.ring.Front()
		}
		var f *gateFlow
		for range g.ring.Len() {
			if c := e.Value.(*gateFlow); c.inFlight < g.perFlow {
				f = c
				break
			}
			if e = e.Next(); e == nil {
				e = g.ring.Front()
			}
		}
		if f == nil {
			return // every flow with waiters already holds its share
		}
		g.next = f.turn.Next()
		w := f.waiters.Front().Value.(*gateWaiter)
		g.dequeueLocked(f, w)
		w.granted = true
		g.grantLocked(f)
		close(w.ready)
	}
}

func (g *Gate) releaser(f *gateFlow) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			f.inFlight--
			g.inFlight--
			addMetric(g.metrics.InFlight, -1)
			g.dispatchLocked()
			g.dropIfIdleLocked(f)
		})
	}
}

// GateFlowSnapshot is one flow's state at the moment of a Snapshot.
type GateFlowSnapshot struct {
	Flow     string `json:"flow"`
	InFlight int    `json:"in_flight"`
	Queued   int    `json:"queued"`
	// Refused counts this flow's 429s and 503s since its state was created,
	// which is since the flow last had nothing in flight or queued.
	Refused int64 `json:"refused"`
}

// GateSnapshot is the gate's state for an operator chasing a noisy tenant:
// the totals and the busiest flows by name. It is for /debug/vars (fleet
// admin only), never a metric: flow names would be unbounded labels.
type GateSnapshot struct {
	Limit        int                `json:"limit"`
	PerFlowLimit int                `json:"per_tenant_limit"`
	QueueWaitMS  int64              `json:"queue_wait_ms"`
	InFlight     int                `json:"in_flight"`
	Queued       int                `json:"queued"`
	Flows        int                `json:"tenants"`
	Busiest      []GateFlowSnapshot `json:"busiest"`
}

// Snapshot returns the gate's totals and its top busiest flows: most
// refused first, then most queued, then most in flight. The zero snapshot
// for a nil gate.
func (g *Gate) Snapshot(top int) GateSnapshot {
	if g == nil {
		return GateSnapshot{}
	}
	g.mu.Lock()
	snap := GateSnapshot{
		Limit: g.limit, PerFlowLimit: g.perFlow, QueueWaitMS: g.wait.Milliseconds(),
		InFlight: g.inFlight, Queued: g.queued, Flows: len(g.flows),
		Busiest: make([]GateFlowSnapshot, 0, len(g.flows)),
	}
	for _, f := range g.flows {
		snap.Busiest = append(snap.Busiest, GateFlowSnapshot{Flow: f.key, InFlight: f.inFlight, Queued: f.waiters.Len(), Refused: f.refused})
	}
	g.mu.Unlock()
	slices.SortFunc(snap.Busiest, func(a, b GateFlowSnapshot) int {
		return cmp.Or(cmp.Compare(b.Refused, a.Refused), cmp.Compare(b.Queued, a.Queued),
			cmp.Compare(b.InFlight, a.InFlight), cmp.Compare(a.Flow, b.Flow))
	})
	if top >= 0 && len(snap.Busiest) > top {
		snap.Busiest = snap.Busiest[:top]
	}
	return snap
}

func addMetric(v *expvar.Int, delta int64) {
	if v != nil {
		v.Add(delta)
	}
}

func setMetric(v *expvar.Int, value int64) {
	if v != nil {
		v.Set(value)
	}
}
