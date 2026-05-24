package ingressproxy

import (
	"expvar"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
)

// Result labels for aerolvm_ask_requests_total. Bounded set — the
// expvar map key space cannot grow with traffic, only with code paths.
const (
	AskResultOK           = "ok"            // 200 — hostname recognised, Caddy may issue
	AskResultBaseDomain   = "base_domain"   // 200 — request is under SB_DOMAIN, served by wildcard policy
	AskResultUnknown      = "unknown"       // 403 — hostname not in FSM/store
	AskResultBadRequest   = "bad_request"   // 400 — missing/malformed query
	AskResultResolveError = "resolve_error" // 500 — resolver transient outage
	AskResultThrottled    = "throttled"     // 429 — daemon ACME budget exhausted
)

var (
	// aerolvm_ask_requests_total{result} — TLSAsk hit counter. F4 alert
	// pivots on the absence of any incoming asks: if the loopback
	// listener crashes mid-process but sandboxd keeps running, every
	// new HTTPS connection fails TLS until restart. The counter going
	// flat while up==1 is the canary.
	askRequestsTotal = expvar.NewMap("aerolvm_ask_requests_total")

	// aerolvm_acme_lock_acquire_duration_seconds_bucket — histogram of
	// issuance durations seen from sandboxd's vantage point (Started →
	// Completed). Bounded by the cert-renew SLO; persistently long
	// observations indicate either LE backoff or certmagic-s3 lock
	// contention.
	acmeLockAcquireSeconds = scaleobs.NewDurationBuckets("aerolvm_acme_lock_acquire_duration_seconds_bucket")

	// defaultIssuanceTracker is process-global. Tests use newIssuanceTracker
	// directly. We expose Recorder-style helpers so callers don't have to
	// know the tracker exists.
	defaultIssuanceTracker = newIssuanceTracker()
)

// RecordAskResult bumps the per-result counter. Use the AskResult*
// constants — adding a freeform string would explode the label space.
func RecordAskResult(result string) {
	scaleobs.Add(askRequestsTotal, result, 1)
}

// DefaultIssuanceTracker returns the process-global tracker that
// publishes the aerolvm_acme_lock_held_seconds gauge. Wire this into
// TLSAskDeps.Tracker in production. Tests should build a private
// tracker via newIssuanceTrackerWithGauge so they don't share state.
func DefaultIssuanceTracker() IssuanceObserver {
	return defaultIssuanceTracker
}

// RecordIssuanceStart marks the moment TLSAsk allowed a previously
// unseen hostname to attempt issuance. Safe to call repeatedly — the
// first call wins (subsequent are no-ops until Completed/Cancel).
func RecordIssuanceStart(hostname string) {
	defaultIssuanceTracker.Started(hostname)
}

// RecordIssuanceCompleted records the issuance duration into the
// histogram and clears the held-seconds gauge. Idempotent — calling
// for an untracked host is a no-op.
func RecordIssuanceCompleted(hostname string) {
	defaultIssuanceTracker.completed(hostname)
}

// issuanceTracker is the backing state for aerolvm_acme_lock_held_seconds.
// We don't have direct hooks into certmagic-s3 from sandboxd (Caddy runs
// in a separate process), so the metric is a best-effort observation
// rooted in the TLSAsk handshake: an OK response to ask is the moment
// the upstream Caddy may start the ACME flow, and we don't see the lock
// release until the service layer transitions the row to ready.
//
// Concurrency: a single mutex guards both the timestamp map and the
// expvar map. The expvar map publishes one Func per active hostname
// that recomputes (now - started).Seconds() at scrape time — the gauge
// is a snapshot, never a stored value.
//
// Bounded growth: RecordIssuanceCompleted is the canonical drain, but it
// has no production caller yet (status reconciliation against certmagic
// storage is a follow-up). To keep the gauge map from leaking one entry
// per unique custom hostname ever observed, Started auto-expires entries
// older than issuanceMaxAge on each insertion. An entry past the age is
// strictly stale telemetry — a real ACME flow that took > 10 minutes is
// already a Prometheus alert on aerolvm_acme_lock_held_seconds.
const issuanceMaxAge = 10 * time.Minute

type issuanceTracker struct {
	mu        sync.Mutex
	startedAt map[string]time.Time
	gauge     *expvar.Map
	now       func() time.Time
}

func newIssuanceTracker() *issuanceTracker {
	return newIssuanceTrackerWithGauge(expvar.NewMap("aerolvm_acme_lock_held_seconds"))
}

// newIssuanceTrackerWithGauge lets tests inject a private expvar.Map so
// they don't double-register the global name (expvar.NewMap panics on
// duplicate names — single-registration is intentional for the production
// path).
func newIssuanceTrackerWithGauge(gauge *expvar.Map) *issuanceTracker {
	return &issuanceTracker{
		startedAt: make(map[string]time.Time),
		gauge:     gauge,
		now:       time.Now,
	}
}

// Started implements IssuanceObserver — the moment TLSAsk allowed a
// previously unseen hostname to attempt issuance. Idempotent.
func (t *issuanceTracker) Started(host string) {
	if host == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.evictStaleLocked()
	if _, ok := t.startedAt[host]; ok {
		return
	}
	now := t.now()
	t.startedAt[host] = now
	// Capture the start in a Func so /debug/vars returns the
	// up-to-date held duration at scrape time, not a stale value.
	t.gauge.Set(host, expvar.Func(func() any {
		t.mu.Lock()
		started, ok := t.startedAt[host]
		t.mu.Unlock()
		if !ok {
			return 0.0
		}
		return t.now().Sub(started).Seconds()
	}))
}

// evictStaleLocked drops entries older than issuanceMaxAge so the gauge
// map stays bounded even without a hookup from the eventual ready/failed
// transition. Caller must hold t.mu.
func (t *issuanceTracker) evictStaleLocked() {
	if len(t.startedAt) == 0 {
		return
	}
	cutoff := t.now().Add(-issuanceMaxAge)
	for host, started := range t.startedAt {
		if started.Before(cutoff) {
			delete(t.startedAt, host)
			t.gauge.Delete(host)
		}
	}
}

func (t *issuanceTracker) completed(host string) {
	if host == "" {
		return
	}
	t.mu.Lock()
	started, ok := t.startedAt[host]
	if ok {
		delete(t.startedAt, host)
	}
	now := t.now()
	t.mu.Unlock()
	if !ok {
		return
	}
	t.gauge.Delete(host)
	acmeLockAcquireSeconds.Observe(now.Sub(started))
}

// inProgress returns the count of currently-tracked hostnames. Test-only.
func (t *issuanceTracker) inProgress() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.startedAt)
}
