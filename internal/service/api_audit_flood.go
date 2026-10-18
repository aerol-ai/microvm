package service

import (
	"expvar"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// Flood control for kind "api" records (plans/identity-and-access.md §5.9,
// CEO review D14). An agent can call exec hundreds of times a second; one
// record per call would let one busy sandbox fill the node's shared
// evidence file and push other tenants' records into gaps. Three modes,
// chosen per install with SB_AUDIT_API_FLOOD_CONTROL:
//
//   - budget (default): the per-sandbox evidence budget the egress records
//     already have (secret_audit_quota.go), with an api bucket keyed by
//     (sandbox, caller). Over budget, calls are counted into one
//     rate_limited record that names the caller, the count and the routes.
//   - coalesce: identical calls (same caller, route, sandbox, status,
//     digest, ...) within one second become one record with request.count.
//     Different commands never merge. No cap.
//   - both: coalesce first, then the budget.
//
// A node that hosts sandboxes of more than one owner always budgets: the
// log is per machine, so an uncapped flood from one customer could push
// another's records out. The service decides the effective mode and sets it
// here; this type only applies it.
//
// Like the egress budget, it runs on the writer goroutine at the one funnel
// every record passes, so nothing routes around it, and it needs no lock.
// Durable records (token create and revoke, sandbox delete under
// SB_AUDIT_API_DURABLE) and records with no sandbox (token and cluster admin
// calls, rare and admin-only) are never budgeted or merged.

const (
	// apiCoalesceWindow is how long identical calls keep merging into one
	// record before it is written.
	apiCoalesceWindow = time.Second
	// apiCoalesceMaxPending bounds the calls held for merging. Past it a
	// call is written on its own: the cap protects memory, never the record.
	apiCoalesceMaxPending = 10_000
	// apiRateLimitMaxRoutes bounds the routes one rate_limited record lists.
	apiRateLimitMaxRoutes = 16
)

// apiFloodMode is a resolved SB_AUDIT_API_FLOOD_CONTROL value.
type apiFloodMode int32

const (
	apiFloodBudget apiFloodMode = iota + 1
	apiFloodCoalesce
	apiFloodBoth
)

func parseAPIFloodMode(raw string) apiFloodMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case config.AuditAPIFloodCoalesce:
		return apiFloodCoalesce
	case config.AuditAPIFloodBoth:
		return apiFloodBoth
	}
	return apiFloodBudget
}

func (m apiFloodMode) String() string {
	switch m {
	case apiFloodCoalesce:
		return config.AuditAPIFloodCoalesce
	case apiFloodBoth:
		return config.AuditAPIFloodBoth
	}
	return config.AuditAPIFloodBudget
}

func (m apiFloodMode) coalesces() bool { return m == apiFloodCoalesce || m == apiFloodBoth }
func (m apiFloodMode) budgets() bool   { return m == apiFloodBudget || m == apiFloodBoth }

// effectiveAPIFloodMode is the shared-node rule: more than one owner on the
// node turns coalesce-only into both.
func effectiveAPIFloodMode(configured apiFloodMode, owners int) apiFloodMode {
	if configured == apiFloodCoalesce && owners > 1 {
		return apiFloodBoth
	}
	return configured
}

var (
	// auditAPIRateLimitedTotal counts api records the budget did not write
	// one by one; each is reported in a rate_limited record.
	auditAPIRateLimitedTotal = expvar.NewInt("aerolvm_audit_api_rate_limited_total")
	auditAPICoalescedTotal   = expvar.NewInt("aerolvm_audit_api_coalesced_total")
)

type apiBudgetEntry struct {
	lim             *rate.Limiter
	suppressed      int64
	firstSuppressed time.Time
	lastSeen        time.Time
	// For the rate_limited record, from the refused calls.
	caller                                            auditlog.Caller
	actor, nodeID, sandboxID, incarnationID, ownerRef string
	routes                                            map[string]struct{}
	denied, failed                                    bool
}

// apiCoalesceKey is everything that tells two calls apart as evidence; only
// the time, event id and correlation id may differ between merged calls.
type apiCoalesceKey struct {
	caller                                  auditlog.Caller
	ref, sandboxID, incarnationID, ownerRef string
	method, route, digest, surface, target  string
	argv                                    string
	result                                  string
	status                                  int
}

type apiCoalesceEntry struct {
	first auditlog.Event
	at    time.Time // when the first call arrived, on the control's clock
	count int64
}

// apiFloodControl is owned by the writer goroutine, except mode, which the
// service sets from any goroutine.
type apiFloodControl struct {
	mode atomic.Int32

	limit       rate.Limit
	burst       int
	markerDelay time.Duration
	buckets     map[string]*apiBudgetEntry
	lastSweep   time.Time

	window  time.Duration
	pending map[apiCoalesceKey]*apiCoalesceEntry
	// nextDue is when the oldest pending merge's window closes, so the
	// per-batch check skips the map until something is due.
	nextDue time.Time

	now func() time.Time
}

func newAPIFloodControl(mode apiFloodMode, perSecond float64, burst int, markerDelay time.Duration) *apiFloodControl {
	if perSecond <= 0 {
		perSecond = 20
	}
	if burst < 1 {
		burst = 100
	}
	if markerDelay <= 0 {
		markerDelay = egressQuotaMarkerDelay
	}
	c := &apiFloodControl{
		limit:       rate.Limit(perSecond),
		burst:       burst,
		markerDelay: markerDelay,
		buckets:     map[string]*apiBudgetEntry{},
		window:      apiCoalesceWindow,
		pending:     map[apiCoalesceKey]*apiCoalesceEntry{},
		now:         time.Now,
	}
	c.setMode(mode)
	return c
}

func (c *apiFloodControl) setMode(m apiFloodMode) {
	if c != nil {
		c.mode.Store(int32(m))
	}
}

func (c *apiFloodControl) currentMode() apiFloodMode {
	if c == nil {
		return 0
	}
	return apiFloodMode(c.mode.Load())
}

// subjectToAPIFlood reports whether a record may be merged or budgeted: an
// api call record about a sandbox that is not itself a summary.
func subjectToAPIFlood(ev auditlog.Event) bool {
	return ev.Kind == auditlog.KindAPI && strings.TrimSpace(ev.SandboxID) != "" &&
		ev.Reason != auditlog.ReasonRateLimited && ev.Dropped == 0 &&
		(ev.Request == nil || ev.Request.Count == 0)
}

// absorb decides one non-durable record. true means it is not written now:
// it is held to merge with identical calls, or the budget refused it and
// counted it. A nil control writes everything.
func (c *apiFloodControl) absorb(ev auditlog.Event) bool {
	if c == nil || !subjectToAPIFlood(ev) {
		return false
	}
	mode := c.currentMode()
	now := c.now()
	if mode.coalesces() {
		key := apiCoalesceKeyOf(ev)
		if e, ok := c.pending[key]; ok {
			e.count++
			auditAPICoalescedTotal.Add(1)
			return true
		}
		if len(c.pending) < apiCoalesceMaxPending {
			c.pending[key] = &apiCoalesceEntry{first: ev, at: now, count: 1}
			if at := now.Add(c.window); c.nextDue.IsZero() || at.Before(c.nextDue) {
				c.nextDue = at
			}
			return true
		}
	}
	if mode.budgets() {
		return !c.spend(ev, now)
	}
	return false
}

// spend charges ev to its (sandbox, caller) bucket. false means over budget:
// the call is counted for the next rate_limited record instead.
func (c *apiFloodControl) spend(ev auditlog.Event, now time.Time) bool {
	e := c.bucket(ev, now)
	if e == nil || e.lim.AllowN(now, 1) {
		return true
	}
	if e.suppressed == 0 {
		e.firstSuppressed = now
	}
	e.suppressed++
	e.actor, e.nodeID = ev.Actor, ev.NodeID
	e.incarnationID, e.ownerRef = ev.IncarnationID, ev.OwnerRef
	if len(e.routes) < apiRateLimitMaxRoutes {
		if e.routes == nil {
			e.routes = map[string]struct{}{}
		}
		e.routes[ev.Ref] = struct{}{}
	}
	switch ev.Result {
	case auditlog.APIResultDenied:
		e.denied = true
	case auditlog.APIResultError:
		e.failed = true
	}
	auditAPIRateLimitedTotal.Add(1)
	return false
}

func apiBudgetKey(ev auditlog.Event) string {
	callerID := ""
	if ev.Caller != nil {
		callerID = ev.Caller.Kind + "\x00" + ev.Caller.ID
	}
	return strings.TrimSpace(ev.SandboxID) + "\x00" + callerID
}

// bucket returns the (sandbox, caller) bucket, creating it under the size
// cap. nil means "untracked, admit": the map is full of live callers.
func (c *apiFloodControl) bucket(ev auditlog.Event, now time.Time) *apiBudgetEntry {
	key := apiBudgetKey(ev)
	if e, ok := c.buckets[key]; ok {
		e.lastSeen = now
		return e
	}
	if len(c.buckets) >= egressQuotaMaxEntries {
		c.sweep(now, true)
		if len(c.buckets) >= egressQuotaMaxEntries {
			return nil
		}
	}
	e := &apiBudgetEntry{lim: rate.NewLimiter(c.limit, c.burst), lastSeen: now, sandboxID: strings.TrimSpace(ev.SandboxID)}
	if ev.Caller != nil {
		e.caller = *ev.Caller
	}
	c.buckets[key] = e
	return e
}

// owed returns every record due now: the merged calls whose window closed
// (all of them with force, for Sync and shutdown), then one rate_limited
// record per bucket whose refused count has aged past the marker delay
// (every owed one with force). Called on the writer's ticker, Sync and
// shutdown; the marker pass walks every bucket, so it is not run per batch.
func (c *apiFloodControl) owed(force bool) []auditlog.Event {
	if c == nil {
		return nil
	}
	now := c.now()
	out := c.dueMergedAt(now, force)
	out = append(out, c.markers(now, force)...)
	c.sweep(now, false)
	return out
}

// dueMerged returns the merged calls whose one-second window closed. It is
// cheap when nothing is due (one time compare), so the writer calls it
// after every batch.
func (c *apiFloodControl) dueMerged() []auditlog.Event {
	if c == nil || len(c.pending) == 0 {
		return nil
	}
	now := c.now()
	if now.Before(c.nextDue) {
		return nil
	}
	return c.dueMergedAt(now, false)
}

// dueMergedAt takes the due merged calls out of pending, oldest first, and
// passes each through the budget when the mode has one ("coalesce first,
// then the budget").
func (c *apiFloodControl) dueMergedAt(now time.Time, force bool) []auditlog.Event {
	if len(c.pending) == 0 {
		return nil
	}
	var due []*apiCoalesceEntry
	c.nextDue = time.Time{}
	for key, e := range c.pending {
		if force || now.Sub(e.at) >= c.window {
			due = append(due, e)
			delete(c.pending, key)
			continue
		}
		if at := e.at.Add(c.window); c.nextDue.IsZero() || at.Before(c.nextDue) {
			c.nextDue = at
		}
	}
	// Map order is random; the chain should not be.
	sort.SliceStable(due, func(i, j int) bool { return due[i].at.Before(due[j].at) })
	budget := c.currentMode().budgets()
	out := make([]auditlog.Event, 0, len(due))
	for _, e := range due {
		ev := e.first
		if e.count > 1 {
			req := auditlog.Request{}
			if ev.Request != nil {
				req = *ev.Request
			}
			req.Count = e.count
			ev.Request = &req
		}
		if budget && !c.spend(e.first, now) {
			// spend counted the first call; the rest the record stood for
			// are over budget with it.
			if b := c.buckets[apiBudgetKey(e.first)]; b != nil && e.count > 1 {
				b.suppressed += e.count - 1
				auditAPIRateLimitedTotal.Add(e.count - 1)
			}
			continue
		}
		out = append(out, ev)
	}
	return out
}

func (c *apiFloodControl) markers(now time.Time, force bool) []auditlog.Event {
	var out []auditlog.Event
	for _, e := range c.buckets {
		if e.suppressed == 0 || (!force && now.Sub(e.firstSuppressed) < c.markerDelay) {
			continue
		}
		routes := make([]string, 0, len(e.routes))
		for r := range e.routes {
			routes = append(routes, r)
		}
		sort.Strings(routes)
		result := auditlog.APIResultOK
		switch {
		case e.denied:
			result = auditlog.APIResultDenied
		case e.failed:
			result = auditlog.APIResultError
		}
		caller := e.caller
		out = append(out, auditlog.Event{
			Time:          now,
			Actor:         e.actor,
			NodeID:        e.nodeID,
			SandboxID:     e.sandboxID,
			IncarnationID: e.incarnationID,
			OwnerRef:      e.ownerRef,
			Kind:          auditlog.KindAPI,
			Result:        result,
			Reason:        auditlog.ReasonRateLimited,
			Dropped:       e.suppressed,
			Caller:        &caller,
			Request:       &auditlog.Request{Routes: routes},
		})
		e.suppressed = 0
		e.firstSuppressed = time.Time{}
		e.routes = nil
		e.denied, e.failed = false, false
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SandboxID != out[j].SandboxID {
			return out[i].SandboxID < out[j].SandboxID
		}
		return out[i].Caller.ID < out[j].Caller.ID
	})
	return out
}

// sweep drops buckets idle past the TTL that owe nothing, at most once per
// egressQuotaSweepEvery unless forced by the size cap.
func (c *apiFloodControl) sweep(now time.Time, force bool) {
	if !force && now.Sub(c.lastSweep) < egressQuotaSweepEvery {
		return
	}
	c.lastSweep = now
	for key, e := range c.buckets {
		if e.suppressed == 0 && now.Sub(e.lastSeen) > egressQuotaIdleTTL {
			delete(c.buckets, key)
		}
	}
}

func apiCoalesceKeyOf(ev auditlog.Event) apiCoalesceKey {
	k := apiCoalesceKey{
		ref:           ev.Ref,
		sandboxID:     ev.SandboxID,
		incarnationID: ev.IncarnationID,
		ownerRef:      ev.OwnerRef,
		result:        ev.Result,
	}
	if ev.Caller != nil {
		k.caller = *ev.Caller
	}
	if r := ev.Request; r != nil {
		k.method, k.route, k.digest = r.Method, r.Route, r.Digest
		k.surface, k.target, k.status = r.Surface, r.Target, r.Status
		k.argv = strings.Join(r.Argv, "\x00")
	}
	return k
}
