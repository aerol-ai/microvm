package netsplice

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func fixed(n int) func() int { return func() int { return n } }

func TestLimiterCaps(t *testing.T) {
	tests := []struct {
		name     string
		perKey   int
		global   int
		acquires []string // keys, in order; nothing is released
		want     []bool
	}{
		{name: "per-key cap", perKey: 2, global: 10,
			acquires: []string{"a", "a", "a", "b"}, want: []bool{true, true, false, true}},
		{name: "global cap across keys", perKey: 10, global: 3,
			acquires: []string{"a", "b", "c", "d", "a"}, want: []bool{true, true, true, false, false}},
		{name: "per-key cap does not borrow from other keys", perKey: 1, global: 3,
			acquires: []string{"a", "a", "b", "b", "c"}, want: []bool{true, false, true, false, true}},
		{name: "zero cap refuses everything", perKey: 0, global: 10,
			acquires: []string{"a"}, want: []bool{false}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := NewLimiter(fixed(tc.perKey), fixed(tc.global))
			for i, key := range tc.acquires {
				release, ok := l.TryAcquire(key, nil, nil)
				if ok != tc.want[i] {
					t.Fatalf("acquire #%d (%s) = %v, want %v", i, key, ok, tc.want[i])
				}
				if ok != (release != nil) {
					t.Fatalf("acquire #%d (%s): ok=%v but release nil=%v", i, key, ok, release == nil)
				}
			}
		})
	}
}

// The caps are read on every acquire: the wake proxy builds its limiters
// once and its config can change afterwards.
func TestLimiterReadsCapsPerAcquire(t *testing.T) {
	var perKey atomic.Int64
	perKey.Store(1)
	l := NewLimiter(func() int { return int(perKey.Load()) }, fixed(10))
	if _, ok := l.TryAcquire("a", nil, nil); !ok {
		t.Fatal("first acquire refused")
	}
	if _, ok := l.TryAcquire("a", nil, nil); ok {
		t.Fatal("cap 1 not enforced")
	}
	perKey.Store(2)
	if _, ok := l.TryAcquire("a", nil, nil); !ok {
		t.Fatal("raised cap not picked up")
	}
}

func TestLimiterCapsHooksAndIdempotentRelease(t *testing.T) {
	l := NewLimiter(fixed(2), fixed(3))
	var events []string
	acq := func(key string) func() {
		t.Helper()
		release, ok := l.TryAcquire(key,
			func(first bool) {
				events = append(events, key+":acquire:"+map[bool]string{true: "first", false: "more"}[first])
			},
			func(last bool) {
				events = append(events, key+":release:"+map[bool]string{true: "last", false: "more"}[last])
			})
		if !ok {
			t.Fatalf("acquire %s refused", key)
		}
		return release
	}
	a1, a2 := acq("a"), acq("a")
	if _, ok := l.TryAcquire("a", nil, nil); ok {
		t.Fatal("per-key cap 2 not enforced")
	}
	b1 := acq("b")
	if _, ok := l.TryAcquire("c", nil, nil); ok {
		t.Fatal("global cap 3 not enforced")
	}
	a1()
	a1() // idempotent: must not release a2's slot
	l.WithLock("a", func(n int) {
		if n != 1 {
			t.Fatalf("count(a) = %d after double release of one slot, want 1", n)
		}
	})
	a2()
	b1()
	l.WithLock("a", func(n int) {
		if n != 0 || l.global != 0 || len(l.byKey) != 0 {
			t.Fatalf("leaked state: count=%d global=%d keys=%v", n, l.global, l.byKey)
		}
	})
	want := []string{"a:acquire:first", "a:acquire:more", "b:acquire:first", "a:release:more", "a:release:last", "b:release:last"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("hook order = %v, want %v", events, want)
	}
}

// The hooks run under the limiter's lock, so state they guard changes
// atomically with the count. The wake proxy ties its activity generation to
// the first acquire and last release that way, and reads it with WithLock.
func TestLimiterHooksRunUnderLock(t *testing.T) {
	l := NewLimiter(fixed(10), fixed(10))
	assertLocked := func(hook string) {
		if l.mu.TryLock() {
			l.mu.Unlock()
			t.Errorf("%s ran without the limiter lock", hook)
		}
	}
	generation := map[string]int{}
	release, ok := l.TryAcquire("a", func(first bool) {
		assertLocked("onAcquire")
		if first {
			generation["a"] = 1
		}
	}, func(last bool) {
		assertLocked("onRelease")
		if last {
			delete(generation, "a")
		}
	})
	if !ok {
		t.Fatal("acquire refused")
	}
	l.WithLock("a", func(count int) {
		assertLocked("WithLock")
		if count != 1 || generation["a"] != 1 {
			t.Fatalf("count=%d generation=%d, want both set together", count, generation["a"])
		}
	})
	release()
	l.WithLock("a", func(count int) {
		if count != 0 || len(generation) != 0 {
			t.Fatalf("count=%d generation=%v after the last release, want both cleared", count, generation)
		}
	})
}

func TestLimiterConcurrentAcquireRelease(t *testing.T) {
	l := NewLimiter(fixed(1<<20), fixed(1<<20))
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := []string{"x", "y"}[i%2]
			for j := 0; j < 200; j++ {
				release, ok := l.TryAcquire(key, nil, nil)
				if !ok {
					t.Error("unexpected refusal")
					return
				}
				release()
				release()
			}
		}(i)
	}
	wg.Wait()
	if l.global != 0 || len(l.byKey) != 0 {
		t.Fatalf("leaked after concurrent churn: global=%d keys=%v", l.global, l.byKey)
	}
}

// The proxies hold a slot for the life of one spliced connection
// (acquire, defer release, Splice). Once the connection closes, the slot is
// free again, for that key and globally.
func TestLimiterReleasesWhenSpliceEnds(t *testing.T) {
	l := NewLimiter(fixed(1), fixed(1))
	clientSide, downstream := loopbackPair(t)
	upstream, backend := loopbackPair(t)
	release, ok := l.TryAcquire("sb", nil, nil)
	if !ok {
		t.Fatal("acquire refused")
	}
	done := make(chan error, 1)
	go func() {
		// The proxy shape; done is sent after the deferred release ran.
		done <- func() error {
			defer release()
			return Splice(downstream, upstream, nil)
		}()
	}()
	if _, ok := l.TryAcquire("other", nil, nil); ok {
		t.Fatal("global cap 1 not enforced while the connection is open")
	}
	_ = clientSide.Close()
	_ = backend.Close()
	waitSplice(t, done, nil)
	if _, ok := l.TryAcquire("sb", nil, nil); !ok {
		t.Fatal("per-key slot not released after the spliced connection closed")
	}
	l.WithLock("other", func(int) {
		if l.global != 1 {
			t.Fatalf("global = %d, want 1 (only the re-acquired slot)", l.global)
		}
	})
}
