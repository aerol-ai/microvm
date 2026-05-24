package service

import (
	"log/slog"
	"sync"
	"time"
)

// ACMEBudget is the daemon-wide brake on new-cert issuance for custom
// hostnames (plan §5b / OV5A). Let's Encrypt enforces a per-account
// `new-orders` limit (300 / 3h rolling). One misconfigured tenant adding
// 100 custom domains can drain that window for the whole cluster, so
// every TLSAsk hit that would trigger a new ACME order (status != ready)
// passes through Reserve; the hot path is the wildcard fast-fail and the
// negative cache, not this bucket.
//
// Semantics:
//   - Sliding window over the LE rolling limit (capacity attempts per
//     window). At capacity*fraction (default 0.8 — 240/300) we refuse,
//     returning a Retry-After equal to the time the oldest in-window
//     attempt ages out. The 20% headroom buys the in-flight renewals
//     (cert-magic kicks them off ~30 days before expiry) survival room.
//   - Per-node bucket, NOT raft-synced. LE limits are per-account, not
//     per-IP, and certmagic-s3's distributed lock already serialises
//     simultaneous issuance for the same hostname across nodes; a node-
//     local bucket is the right granularity for "this node is about to
//     burn the account."
//   - Observation, not metering: a single Reserve call corresponds to one
//     TLSAsk that COULD trigger issuance. Caddy may rate-limit further
//     before actually opening an order, and certmagic dedupes
//     simultaneous orders for the same host. Treat the bucket as an
//     upper bound on issuance rate, not the exact count.
type ACMEBudget struct {
	mu        sync.Mutex
	window    time.Duration
	capacity  int
	threshold int
	attempts  []time.Time // append-only within window; pruned on Reserve
	logger    *slog.Logger
	now       func() time.Time
	// onThrottle is called when Reserve denies. Test hook.
	onThrottle func(sandboxID string, retryAfter time.Duration)
}

// ACMEBudgetConfig captures the operator-facing knobs.
type ACMEBudgetConfig struct {
	Capacity int
	Window   time.Duration
	Fraction float64
	Logger   *slog.Logger
}

// NewACMEBudget builds a budget. A nil result is safe: budget == nil
// implies "no daemon-wide brake" (Reserve degrades to always-allow), so
// the TLSAsk hot path stays single-branch when the feature is off.
func NewACMEBudget(cfg ACMEBudgetConfig) *ACMEBudget {
	if cfg.Capacity <= 0 || cfg.Window <= 0 || cfg.Fraction <= 0 || cfg.Fraction >= 1 {
		return nil
	}
	threshold := max(int(float64(cfg.Capacity)*cfg.Fraction), 1)
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &ACMEBudget{
		window:    cfg.Window,
		capacity:  cfg.Capacity,
		threshold: threshold,
		attempts:  make([]time.Time, 0, threshold),
		logger:    logger,
		now:       time.Now,
	}
}

// Reserve records an attempt and returns (true, 0) if the new attempt
// keeps the bucket below threshold, or (false, retryAfter) if it would
// cross. sandboxID is logged on denial so the operator can spot the
// burner. retryAfter is the time until the oldest in-window attempt ages
// out — the earliest moment another attempt could succeed.
//
// A nil *ACMEBudget always allows: makes the call site one-liner.
func (b *ACMEBudget) Reserve(sandboxID, hostname string) (bool, time.Duration) {
	if b == nil {
		return true, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	cutoff := now.Add(-b.window)
	// Prune ageing-out attempts. The slice is append-only in time-order,
	// so a single forward scan finds the first still-in-window index.
	i := 0
	for i < len(b.attempts) && b.attempts[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		b.attempts = append(b.attempts[:0], b.attempts[i:]...)
	}

	if len(b.attempts) >= b.threshold {
		// Oldest in-window attempt drives the earliest opening. If the
		// slice is empty (shouldn't be reachable since len >= threshold
		// >= 1) the caller still gets a sane non-zero retry.
		retry := b.window
		if len(b.attempts) > 0 {
			retry = max(b.attempts[0].Add(b.window).Sub(now), time.Second)
		}
		b.logger.Warn("acme: daemon budget exhausted, throttling issuance",
			"sandbox_id", sandboxID,
			"hostname", hostname,
			"in_window", len(b.attempts),
			"threshold", b.threshold,
			"capacity", b.capacity,
			"retry_after", retry,
		)
		if b.onThrottle != nil {
			b.onThrottle(sandboxID, retry)
		}
		return false, retry
	}

	b.attempts = append(b.attempts, now)
	return true, 0
}

// InWindow returns the current in-window attempt count. Test-only —
// production callers should not gate on this number; use Reserve.
func (b *ACMEBudget) InWindow() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	cutoff := now.Add(-b.window)
	count := 0
	for _, t := range b.attempts {
		if !t.Before(cutoff) {
			count++
		}
	}
	return count
}

// Threshold returns the denial line. Stable for the life of the budget.
func (b *ACMEBudget) Threshold() int {
	if b == nil {
		return 0
	}
	return b.threshold
}
