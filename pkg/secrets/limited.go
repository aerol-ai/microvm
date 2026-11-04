package secrets

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"
)

// Limiter budgets. Only the foreground cap is a setting
// (SB_SECRET_PROVIDER_MAX_INFLIGHT), because it must fit the customer's key
// store, for example an HSM partition's session limit. The rest are constants
// until measurements give a reason to change them (eng D13).
const (
	// reservedCreateSlots of the foreground cap only a create-path call may
	// take, so a restart storm of opens cannot queue a create behind it.
	reservedCreateSlots = 1
	// backgroundSlots is a separate budget for the re-check and the sweep, so
	// background work never takes a slot a create or an open needs.
	backgroundSlots = 2

	throttleMaxAttempts = 5
	throttleBackoffMin  = 50 * time.Millisecond
	throttleBackoffMax  = 2 * time.Second

	// One retry of an unavailable key store, foreground only (eng D17): it
	// hides a dropped connection or the tail of a Vault handover, not an
	// outage.
	unavailableRetryMin = 100 * time.Millisecond
	unavailableRetryMax = 300 * time.Millisecond
)

// Limiter budget names, used by LimiterObserver.
const (
	BudgetForeground = "foreground"
	BudgetCreate     = "create"
	BudgetBackground = "background"
)

// LimiterObserver is told how long each call waited for a key-store slot.
type LimiterObserver func(budget string, wait time.Duration)

type callKind int

const (
	callForeground callKind = iota
	callCreate
	callBackground
)

type callKindKey struct{}

// ContextForCreate marks ctx as a create-path call, which may use the reserved
// create slot.
func ContextForCreate(ctx context.Context) context.Context {
	return context.WithValue(ctx, callKindKey{}, callCreate)
}

// ContextForBackground marks ctx as background work (re-check, sweep), which
// uses its own budget and never retries an unavailable key store.
func ContextForBackground(ctx context.Context) context.Context {
	return context.WithValue(ctx, callKindKey{}, callBackground)
}

func kindOf(ctx context.Context) callKind {
	if k, ok := ctx.Value(callKindKey{}).(callKind); ok {
		return k
	}
	return callForeground
}

func (k callKind) budget() string {
	switch k {
	case callCreate:
		return BudgetCreate
	case callBackground:
		return BudgetBackground
	default:
		return BudgetForeground
	}
}

// limitedWrapper caps in-flight key-store calls per node and retries the two
// transient classes inside the caller's deadline.
type limitedWrapper struct {
	inner      DataKeyWrapper
	general    chan struct{}
	reserved   chan struct{}
	background chan struct{}
	observe    LimiterObserver
	sleep      func(context.Context, time.Duration) error
	jitter     func(min, max time.Duration) time.Duration
}

// NewLimitedWrapper wraps inner with a foreground cap of maxInFlight (one of
// which is kept for creates when maxInFlight > 1) and a separate background
// budget. observe may be nil.
func NewLimitedWrapper(inner DataKeyWrapper, maxInFlight int, observe LimiterObserver) DataKeyWrapper {
	if maxInFlight < 1 {
		maxInFlight = 1
	}
	reserved := reservedCreateSlots
	if maxInFlight <= reserved {
		reserved = 0
	}
	return &limitedWrapper{
		inner:      inner,
		general:    make(chan struct{}, maxInFlight-reserved),
		reserved:   make(chan struct{}, reserved),
		background: make(chan struct{}, backgroundSlots),
		observe:    observe,
		sleep:      sleepCtx,
		jitter:     jitterBetween,
	}
}

// BackgroundSlots is the size of the background budget, which the PKCS#11
// session pool adds to the foreground cap.
func BackgroundSlots() int { return backgroundSlots }

func (l *limitedWrapper) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	return l.call(ctx, func(ctx context.Context) ([]byte, error) { return l.inner.Wrap(ctx, dek, encCtx) })
}

func (l *limitedWrapper) Unwrap(ctx context.Context, wrapped []byte, encCtx map[string]string) ([]byte, error) {
	return l.call(ctx, func(ctx context.Context) ([]byte, error) { return l.inner.Unwrap(ctx, wrapped, encCtx) })
}

func (l *limitedWrapper) call(ctx context.Context, op func(context.Context) ([]byte, error)) ([]byte, error) {
	if l == nil || l.inner == nil {
		return nil, fmt.Errorf("%w: secret provider wrap backend is not configured", ErrProviderUnavailable)
	}
	kind := kindOf(ctx)
	backoff := throttleBackoffMin
	retriedUnavailable := false
	for attempt := 1; ; attempt++ {
		release, err := l.acquire(ctx, kind)
		if err != nil {
			return nil, err
		}
		out, err := op(ctx)
		release()
		switch {
		case err == nil:
			return out, nil
		case errors.Is(err, ErrProviderThrottled) && attempt < throttleMaxAttempts:
			if serr := l.wait(ctx, l.jitter(backoff/2, backoff)); serr != nil {
				return nil, err
			}
			backoff = min(backoff*2, throttleBackoffMax)
		case errors.Is(err, ErrProviderUnavailable) && kind != callBackground && !retriedUnavailable:
			retriedUnavailable = true
			if serr := l.wait(ctx, l.jitter(unavailableRetryMin, unavailableRetryMax)); serr != nil {
				return nil, err
			}
		default:
			return nil, err
		}
	}
}

// wait sleeps d unless the caller's deadline would expire first, in which case
// it returns at once so the caller reports the original error.
func (l *limitedWrapper) wait(ctx context.Context, d time.Duration) error {
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= d {
		return context.DeadlineExceeded
	}
	return l.sleep(ctx, d)
}

func (l *limitedWrapper) acquire(ctx context.Context, kind callKind) (func(), error) {
	start := time.Now()
	done := func(slot chan struct{}) func() {
		if l.observe != nil {
			l.observe(kind.budget(), time.Since(start))
		}
		return func() { <-slot }
	}
	busy := func() error {
		return fmt.Errorf("%w: waited %s for a %s key-store slot: %v", ErrProviderThrottled, time.Since(start).Round(time.Millisecond), kind.budget(), ctx.Err())
	}
	switch kind {
	case callBackground:
		select {
		case l.background <- struct{}{}:
			return done(l.background), nil
		case <-ctx.Done():
			return nil, busy()
		}
	case callCreate:
		select {
		case l.general <- struct{}{}:
			return done(l.general), nil
		default:
		}
		select {
		case l.general <- struct{}{}:
			return done(l.general), nil
		case l.reserved <- struct{}{}:
			return done(l.reserved), nil
		case <-ctx.Done():
			return nil, busy()
		}
	default:
		select {
		case l.general <- struct{}{}:
			return done(l.general), nil
		case <-ctx.Done():
			return nil, busy()
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func jitterBetween(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(rand.Int64N(int64(hi-lo)))
}
