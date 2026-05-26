package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakePool is the minimal TapPool used by the Create integration tests.
// Records every call so we can assert the allocate-then-release sequence
// on the error path — the load-bearing cleanup contract.
type fakePool struct {
	mu        sync.Mutex
	slots     map[string]*TapSlot
	alloc     int
	release   int
	nextErr   error // injected on next Allocate
	relErr    error // injected on next Release
	lastAlloc string
}

func newFakePool() *fakePool {
	return &fakePool{slots: map[string]*TapSlot{}}
}

func (p *fakePool) Allocate(_ context.Context, sandboxID string, _ time.Time) (*TapSlot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.alloc++
	if p.nextErr != nil {
		err := p.nextErr
		p.nextErr = nil
		return nil, err
	}
	slot := &TapSlot{
		TapName:  "fctap-test",
		CIDR:     "172.16.0.0/30",
		HostIP:   "172.16.0.1",
		GuestIP:  "172.16.0.2",
		VsockCID: 3,
	}
	p.slots[sandboxID] = slot
	p.lastAlloc = sandboxID
	return slot, nil
}

func (p *fakePool) Release(_ context.Context, sandboxID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.release++
	if p.relErr != nil {
		err := p.relErr
		p.relErr = nil
		return err
	}
	delete(p.slots, sandboxID)
	return nil
}

func (p *fakePool) Get(_ context.Context, sandboxID string) (*TapSlot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.slots[sandboxID]; ok {
		return s, nil
	}
	return nil, nil
}

// TestCreate_PoolRequired confirms Create rejects when no pool has been
// injected — that's a daemon-wiring bug (main.go forgot SetPool).
func TestCreate_PoolRequired(t *testing.T) {
	d := New(Config{KernelImage: "/anything"}, nil)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{}, "id", "tok", nil)
	if err == nil {
		t.Fatal("expected error without pool")
	}
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("err should wrap ErrRuntimeNotImplemented, got %v", err)
	}
}

// TestCreate_KernelMissing confirms a missing kernel image fails fast
// with a clear stat error, before touching the pool. Without this
// check, a misconfigured KernelImage would leak a TAP slot on every
// Create attempt.
func TestCreate_KernelMissing(t *testing.T) {
	pool := newFakePool()
	d := New(Config{KernelImage: "/no/such/kernel"}, nil)
	d.SetPool(pool)

	_, err := d.Create(context.Background(), models.CreateSandboxRequest{}, "id", "tok", nil)
	if err == nil {
		t.Fatal("expected error for missing kernel")
	}
	if pool.alloc != 0 || pool.release != 0 {
		t.Errorf("kernel check should run before pool ops; alloc=%d release=%d", pool.alloc, pool.release)
	}
}

// TestCreate_AllocateThenReleaseOnError exercises the Phase 1 cleanup
// contract: Create allocates a slot, returns ErrRuntimeNotImplemented
// for the unfinished VMM-spawn step, and releases the slot before
// returning. A failed Release after an outer error would leak a slot
// per Create attempt, eventually exhausting the pool.
func TestCreate_AllocateThenReleaseOnError(t *testing.T) {
	// Materialize a fake kernel file so the existence check passes.
	tmp := t.TempDir()
	kernel := filepath.Join(tmp, "vmlinux")
	if err := os.WriteFile(kernel, []byte{0}, 0o644); err != nil {
		t.Fatalf("write fake kernel: %v", err)
	}

	pool := newFakePool()
	d := New(Config{KernelImage: kernel}, nil)
	d.SetPool(pool)

	_, err := d.Create(context.Background(), models.CreateSandboxRequest{}, "sb-1", "tok", nil)
	if err == nil {
		t.Fatal("expected ErrRuntimeNotImplemented while VMM spawn is not wired")
	}
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("err should wrap ErrRuntimeNotImplemented, got %v", err)
	}
	if pool.alloc != 1 {
		t.Errorf("alloc count = %d, want 1", pool.alloc)
	}
	if pool.release != 1 {
		t.Errorf("release count = %d, want 1 (cleanup contract violated)", pool.release)
	}
	if pool.lastAlloc != "sb-1" {
		t.Errorf("lastAlloc = %q, want sb-1", pool.lastAlloc)
	}
}

// TestCreate_SynthIDWhenSandboxIDEmpty confirms Create still allocates +
// releases when the service layer passes an empty sandboxID (today's
// firecracker dispatch path doesn't generate an ID before calling the
// driver — the docker path does, in a later phase). The synthesized ID
// must be unique per call so concurrent Phase-1 dispatches don't
// collide on the pool.
func TestCreate_SynthIDWhenSandboxIDEmpty(t *testing.T) {
	tmp := t.TempDir()
	kernel := filepath.Join(tmp, "vmlinux")
	if err := os.WriteFile(kernel, []byte{0}, 0o644); err != nil {
		t.Fatal(err)
	}
	pool := newFakePool()
	d := New(Config{KernelImage: kernel}, nil)
	d.SetPool(pool)

	_, _ = d.Create(context.Background(), models.CreateSandboxRequest{}, "", "tok", nil)
	if pool.alloc != 1 || pool.release != 1 {
		t.Errorf("alloc=%d release=%d, want 1/1", pool.alloc, pool.release)
	}
	if pool.lastAlloc == "" {
		t.Error("expected synthesized ID to be non-empty")
	}
}

// TestCreate_PoolAllocateFailure_DoesNotRelease confirms we don't call
// Release if Allocate failed (no slot to release). A spurious Release
// in this case would mask the original error and could clear a legit
// allocation by a different caller racing on the same synth-ID.
func TestCreate_PoolAllocateFailure_DoesNotRelease(t *testing.T) {
	tmp := t.TempDir()
	kernel := filepath.Join(tmp, "vmlinux")
	if err := os.WriteFile(kernel, []byte{0}, 0o644); err != nil {
		t.Fatal(err)
	}
	pool := newFakePool()
	pool.nextErr = errors.New("pool exhausted")
	d := New(Config{KernelImage: kernel}, nil)
	d.SetPool(pool)

	_, err := d.Create(context.Background(), models.CreateSandboxRequest{}, "sb-x", "tok", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if pool.alloc != 1 || pool.release != 0 {
		t.Errorf("alloc=%d release=%d, want 1/0 (no release after failed allocate)", pool.alloc, pool.release)
	}
}
