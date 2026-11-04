package secrets

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptWrapper returns errs in order, then succeeds; block, when set, holds
// every call until released.
type scriptWrapper struct {
	mu    sync.Mutex
	errs  []error
	calls int
	block chan struct{}
}

func (s *scriptWrapper) next() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if len(s.errs) == 0 {
		return nil
	}
	err := s.errs[0]
	s.errs = s.errs[1:]
	return err
}

func (s *scriptWrapper) Wrap(ctx context.Context, dek []byte, _ map[string]string) ([]byte, error) {
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := s.next(); err != nil {
		return nil, err
	}
	return dek, nil
}

func (s *scriptWrapper) Unwrap(ctx context.Context, w []byte, encCtx map[string]string) ([]byte, error) {
	return s.Wrap(ctx, w, encCtx)
}

func fastLimiter(inner DataKeyWrapper, max int, observe LimiterObserver) *limitedWrapper {
	l := NewLimitedWrapper(inner, max, observe).(*limitedWrapper)
	l.sleep = func(context.Context, time.Duration) error { return nil }
	return l
}

func TestLimiterRetries(t *testing.T) {
	throttled := func(n int) []error {
		out := make([]error, n)
		for i := range out {
			out[i] = ErrProviderThrottled
		}
		return out
	}
	cases := []struct {
		name      string
		ctx       func() context.Context
		errs      []error
		wantErr   error
		wantCalls int
	}{
		{"ok", context.Background, nil, nil, 1},
		{"throttled then ok", context.Background, throttled(2), nil, 3},
		{"throttled past the attempt cap", context.Background, throttled(throttleMaxAttempts), ErrProviderThrottled, throttleMaxAttempts},
		{"unavailable once retried (foreground)", context.Background, []error{ErrProviderUnavailable}, nil, 2},
		{"unavailable twice fails", context.Background, []error{ErrProviderUnavailable, ErrProviderUnavailable}, ErrProviderUnavailable, 2},
		{"unavailable retried on create", func() context.Context { return ContextForCreate(context.Background()) }, []error{ErrProviderUnavailable}, nil, 2},
		{"background never retries unavailable", func() context.Context { return ContextForBackground(context.Background()) }, []error{ErrProviderUnavailable}, ErrProviderUnavailable, 1},
		{"denied is not retried", context.Background, []error{ErrProviderDenied}, ErrProviderDenied, 1},
		{"revoked is not retried", context.Background, []error{ErrKeyRevoked}, ErrKeyRevoked, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &scriptWrapper{errs: tc.errs}
			l := fastLimiter(inner, 4, nil)
			_, err := l.Wrap(tc.ctx(), []byte("dek"), nil)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if inner.calls != tc.wantCalls {
				t.Fatalf("calls = %d, want %d", inner.calls, tc.wantCalls)
			}
		})
	}
}

// A retry never sleeps past the caller's deadline: the original error comes
// back instead.
func TestLimiterRetryRespectsDeadline(t *testing.T) {
	inner := &scriptWrapper{errs: []error{ErrProviderUnavailable}}
	l := NewLimitedWrapper(inner, 2, nil).(*limitedWrapper)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := l.Wrap(ctx, []byte("dek"), nil)
	if !errors.Is(err, ErrProviderUnavailable) || inner.calls != 1 {
		t.Fatalf("err = %v calls = %d, want the first error and no retry", err, inner.calls)
	}
}

// With every general slot busy, a create still gets the reserved slot and a
// plain open waits until its deadline (then reports throttled).
func TestLimiterReservedCreateSlot(t *testing.T) {
	inner := &scriptWrapper{block: make(chan struct{})}
	l := fastLimiter(inner, 2, nil) // 1 general + 1 reserved

	holding := make(chan error, 1)
	go func() { _, err := l.Unwrap(context.Background(), []byte("a"), nil); holding <- err }()
	waitFor(t, func() bool { return len(l.general) == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := l.Unwrap(ctx, []byte("b"), nil)
	if !errors.Is(err, ErrProviderThrottled) || !strings.Contains(err.Error(), "foreground key-store slot") {
		t.Fatalf("open with no free slot = %v", err)
	}

	created := make(chan error, 1)
	go func() { _, err := l.Wrap(ContextForCreate(context.Background()), []byte("c"), nil); created <- err }()
	waitFor(t, func() bool { return len(l.reserved) == 1 })
	close(inner.block)
	if err := <-created; err != nil {
		t.Fatalf("create on the reserved slot = %v", err)
	}
	if err := <-holding; err != nil {
		t.Fatalf("held open = %v", err)
	}
}

// Background work has its own budget: it never takes a foreground slot, and a
// full background budget does not block an open.
func TestLimiterBackgroundBudget(t *testing.T) {
	inner := &scriptWrapper{block: make(chan struct{})}
	var mu sync.Mutex
	waits := map[string]int{}
	l := fastLimiter(inner, 1, func(budget string, _ time.Duration) {
		mu.Lock()
		waits[budget]++
		mu.Unlock()
	})
	if cap(l.reserved) != 0 || cap(l.general) != 1 {
		t.Fatalf("max 1 must not reserve: general %d reserved %d", cap(l.general), cap(l.reserved))
	}
	bg := ContextForBackground(context.Background())
	done := make(chan error, backgroundSlots+1)
	for i := 0; i < backgroundSlots; i++ {
		go func() { _, err := l.Unwrap(bg, []byte("x"), nil); done <- err }()
	}
	waitFor(t, func() bool { return len(l.background) == backgroundSlots })
	if len(l.general) != 0 {
		t.Fatal("background work took a foreground slot")
	}
	ctx, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	if _, err := l.Unwrap(ctx, []byte("y"), nil); !errors.Is(err, ErrProviderThrottled) {
		t.Fatalf("third background call = %v, want throttled", err)
	}
	go func() { _, err := l.Unwrap(context.Background(), []byte("z"), nil); done <- err }()
	waitFor(t, func() bool { return len(l.general) == 1 })
	close(inner.block)
	for i := 0; i < backgroundSlots+1; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if waits[BudgetBackground] != backgroundSlots || waits[BudgetForeground] != 1 {
		t.Fatalf("observed waits = %v", waits)
	}
}

func TestLimiterNilAndHelpers(t *testing.T) {
	var l *limitedWrapper
	if _, err := l.Wrap(context.Background(), nil, nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("nil limiter = %v", err)
	}
	if got := NewLimitedWrapper(nil, 0, nil).(*limitedWrapper); cap(got.general) != 1 {
		t.Fatalf("max 0 must clamp to 1, got general %d", cap(got.general))
	}
	if BackgroundSlots() != backgroundSlots {
		t.Fatal("BackgroundSlots")
	}
	for i := 0; i < 50; i++ {
		d := jitterBetween(10*time.Millisecond, 20*time.Millisecond)
		if d < 10*time.Millisecond || d >= 20*time.Millisecond {
			t.Fatalf("jitter %v out of range", d)
		}
	}
	if jitterBetween(5, 5) != 5 {
		t.Fatal("empty range returns lo")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("sleepCtx on a cancelled ctx = %v", err)
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestNewWrapper(t *testing.T) {
	ctx := context.Background()
	if w, err := NewWrapper(ctx, ProviderOptions{Name: "local"}); w != nil || err != nil {
		t.Fatalf("local = %v %v, want nil nil", w, err)
	}
	for _, name := range []string{"vault", "pkcs11", "bogus"} {
		if _, err := NewWrapper(ctx, ProviderOptions{Name: name}); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	if _, err := NewWrapper(ctx, ProviderOptions{Name: "awskms"}); err == nil {
		t.Fatal("awskms without a key id must fail")
	}
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWrapper(ctx, ProviderOptions{Name: "awskms", Wrapper: fake, MaxInFlight: 3})
	if err != nil {
		t.Fatal(err)
	}
	if lw := w.(*limitedWrapper); cap(lw.general)+cap(lw.reserved) != 3 {
		t.Fatalf("cap = %d", cap(lw.general)+cap(lw.reserved))
	}
	if err := CanaryWrapUnwrap(ctx, w); err != nil {
		t.Fatalf("canary through router and limiter = %v", err)
	}
	p, got, err := NewProvider(ctx, ProviderOptions{Name: "awskms", Store: newMemBlobStore(), Prebuilt: w})
	if err != nil || p == nil || got != w {
		t.Fatalf("NewProvider with Prebuilt = %v %v %v", p, got, err)
	}
	for name, want := range map[string]bool{"": false, "local": false, "AWSKMS": true, "vault": true, "pkcs11": true, "x": false} {
		if IsExternalProvider(name) != want {
			t.Fatalf("IsExternalProvider(%q) != %v", name, want)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}
