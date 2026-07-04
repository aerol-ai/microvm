package wasm

import (
	"context"
	"errors"
	"testing"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
)

type memoryWarmPool struct {
	slot *wasmpool.Slot
}

func (p *memoryWarmPool) NoteModule(string, string) {}

func (p *memoryWarmPool) Acquire(_ context.Context, _, _ string, memoryMB int) (*wasmpool.Slot, error) {
	if p.slot == nil || p.slot.MemoryMB != memoryMB {
		return nil, wasmpool.ErrNoSlot
	}
	s := p.slot
	p.slot = nil
	return s, nil
}

func TestAcquire_MemoryMismatchMisses(t *testing.T) {
	d := New(Config{RunDir: t.TempDir(), ModulesDir: t.TempDir(), DefaultMemoryMB: 256}, nil)
	d.SetWarmPool(&memoryWarmPool{slot: &wasmpool.Slot{
		ID:           "pool-1",
		ModuleDigest: "digest",
		MemoryMB:     256,
	}})

	slot, err := d.tryAcquireWarm(context.Background(), "digest", "/mod.wasm", 512)
	if err != nil {
		t.Fatalf("tryAcquireWarm: %v", err)
	}
	if slot != nil {
		t.Fatalf("expected miss for memory mismatch, got slot %+v", slot)
	}

	d.SetWarmPool(&memoryWarmPool{slot: &wasmpool.Slot{
		ID:           "pool-2",
		ModuleDigest: "digest",
		MemoryMB:     256,
	}})
	slot, err = d.tryAcquireWarm(context.Background(), "digest", "/mod.wasm", 256)
	if err != nil {
		t.Fatalf("tryAcquireWarm match: %v", err)
	}
	if slot == nil || slot.ID != "pool-2" {
		t.Fatalf("slot = %+v, want pool-2", slot)
	}
}

func TestTryAcquireWarm_PoolError(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWarmPool(errWarmPool{})
	_, err := d.tryAcquireWarm(context.Background(), "d", "/p", 256)
	if err == nil {
		t.Fatal("expected warm pool error")
	}
	if !errors.Is(err, errors.New("warm pool broken")) && err.Error() != "warm pool broken" {
		// errWarmPool returns a plain error
		if err.Error() != "warm pool broken" {
			t.Fatalf("err = %v", err)
		}
	}
}
