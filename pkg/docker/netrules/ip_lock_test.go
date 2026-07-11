package netrules

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowExistsBackend delays after a miss so concurrent same-IP BlockAll*
// callers race Exists→Insert without the per-IP lock.
type slowExistsBackend struct {
	memBackend
	delay time.Duration
}

func (s *slowExistsBackend) Exists(table, chain string, spec ...string) (bool, error) {
	ok, err := s.memBackend.Exists(table, chain, spec...)
	if err == nil && !ok && s.delay > 0 {
		time.Sleep(s.delay)
	}
	return ok, err
}

func TestPerIPLockSameIPNoDuplicateInsert(t *testing.T) {
	backend := &slowExistsBackend{delay: 20 * time.Millisecond}
	mgr := NewWithBackend(backend)
	const ip = "10.0.0.42"
	const n = 16

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mgr.BlockAllEgress(ip); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("BlockAllEgress: %v", err)
	}
	if got := backend.countMatching(ip); got != 1 {
		t.Fatalf("rules for %s = %d, want exactly 1 (per-IP lock must serialize Exists+Insert)", ip, got)
	}
	if backend.ruleCount() != 1 {
		t.Fatalf("total rules = %d, want 1", backend.ruleCount())
	}
}

// trackingBackend records peak concurrent Insert depth so we can prove
// different IPs are not serialized on a global mutex.
type trackingBackend struct {
	memBackend
	active    atomic.Int32
	maxActive atomic.Int32
	delay     time.Duration
}

func (t *trackingBackend) Insert(table, chain string, pos int, spec ...string) error {
	n := t.active.Add(1)
	for {
		old := t.maxActive.Load()
		if n <= old || t.maxActive.CompareAndSwap(old, n) {
			break
		}
	}
	if t.delay > 0 {
		time.Sleep(t.delay)
	}
	err := t.memBackend.Insert(table, chain, pos, spec...)
	t.active.Add(-1)
	return err
}

func TestPerIPLockDifferentIPsOverlap(t *testing.T) {
	backend := &trackingBackend{delay: 30 * time.Millisecond}
	mgr := NewWithBackend(backend)
	const n = 8

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		ip := fmt.Sprintf("10.0.1.%d", i+1)
		go func(ip string) {
			defer wg.Done()
			if err := mgr.BlockAllEgress(ip); err != nil {
				errs <- err
			}
		}(ip)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("BlockAllEgress: %v", err)
	}
	if backend.ruleCount() != n {
		t.Fatalf("rules = %d, want %d", backend.ruleCount(), n)
	}
	if backend.maxActive.Load() < 2 {
		t.Fatalf("max concurrent Insert = %d, want ≥2 (different IPs must not share one global lock)", backend.maxActive.Load())
	}
}

func TestPerIPLockReleasedAfterOp(t *testing.T) {
	mgr := NewWithBackend(&memBackend{})
	if err := mgr.BlockAllEgress("10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	mgr.ipMu.Lock()
	left := len(mgr.ipLocks)
	mgr.ipMu.Unlock()
	if left != 0 {
		t.Fatalf("ipLocks left = %d after unlock, want 0 (refcount cleanup)", left)
	}
}
