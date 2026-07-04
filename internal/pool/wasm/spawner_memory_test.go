package wasm

import (
	"context"
	"testing"
	"time"
)

type recordingWarmSpawner struct {
	lastMemoryMB int
}

func (s *recordingWarmSpawner) Warm(_ context.Context, _, _, _ string, memoryMB int) error {
	s.lastMemoryMB = memoryMB
	return nil
}

func (s *recordingWarmSpawner) Shutdown(string) error { return nil }

func TestWarm_PassesMemoryMB(t *testing.T) {
	sp := &recordingWarmSpawner{}
	p := New(t.TempDir(), nil)
	p.SetDefaultMemoryMB(256)
	p.SetSpawner(sp)
	slot, err := p.WarmOne(context.Background(), "digest", "/mod.wasm")
	if err != nil {
		t.Fatalf("WarmOne: %v", err)
	}
	if sp.lastMemoryMB != 256 {
		t.Fatalf("memoryMB = %d, want 256", sp.lastMemoryMB)
	}
	if slot.MemoryMB != 256 {
		t.Fatalf("slot.MemoryMB = %d, want 256", slot.MemoryMB)
	}
}

func TestRefill_KickOnMiss(t *testing.T) {
	p := New(t.TempDir(), nil)
	p.SetDefaultDepth(1)
	p.NoteModule("d1", "/mod.wasm")
	sp := &fakeSpawner{}
	p.SetSpawner(sp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, RefillConfig{RefillInterval: time.Hour, SpawnTimeout: 5 * time.Second}, sp)

	_, err := p.Acquire(context.Background(), "d1", "/mod.wasm", 256)
	if err != ErrNoSlot {
		t.Fatalf("Acquire: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for len(sp.warmed) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(sp.warmed) == 0 {
		t.Fatal("expected miss-kicked refill to warm without waiting for ticker")
	}
}
