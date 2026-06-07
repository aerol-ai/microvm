package wasm

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type fakeSpawner struct {
	warmed []string
}

func (f *fakeSpawner) Warm(_ context.Context, slotID, socketPath, modulePath string) error {
	f.warmed = append(f.warmed, slotID+":"+modulePath)
	return nil
}

func (f *fakeSpawner) Shutdown(string) error { return nil }

func TestPoolAcquireMissAndHit(t *testing.T) {
	p := New(t.TempDir(), nil)
	p.SetDefaultDepth(1)
	p.NoteModule("digest-a", "/tmp/mod.wasm")

	_, err := p.Acquire(context.Background(), "digest-a", "/tmp/mod.wasm")
	if !errors.Is(err, ErrNoSlot) {
		t.Fatalf("first acquire: %v", err)
	}
	if p.Metrics().Stats().Misses != 1 {
		t.Fatalf("misses = %d", p.Metrics().Stats().Misses)
	}

	slot := &Slot{
		ID:           "pool-1",
		ModuleDigest: "digest-a",
		ModulePath:   "/tmp/mod.wasm",
		SocketPath:   filepath.Join(t.TempDir(), "worker.sock"),
		WorkerKey:    "pool-1",
	}
	p.RecordLoaded(slot)

	got, err := p.Acquire(context.Background(), "digest-a", "/tmp/mod.wasm")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if got.ID != slot.ID {
		t.Fatalf("slot id = %q", got.ID)
	}
	if p.Metrics().Stats().Hits != 1 {
		t.Fatalf("hits = %d", p.Metrics().Stats().Hits)
	}
}

func TestPoolSpawnBudget(t *testing.T) {
	p := New(t.TempDir(), nil)
	p.SetDefaultDepth(2)
	p.NoteModule("d1", "/m.wasm")

	if b := p.SpawnBudget("d1"); b != 2 {
		t.Fatalf("initial budget = %d", b)
	}
	p.RecordLoaded(&Slot{ID: "s1", ModuleDigest: "d1"})
	if b := p.SpawnBudget("d1"); b != 1 {
		t.Fatalf("after one ready budget = %d", b)
	}
}

func TestPoolWarmOne(t *testing.T) {
	dir := t.TempDir()
	spawner := &fakeSpawner{}
	p := New(dir, nil)
	p.SetSpawner(spawner)

	slot, err := p.WarmOne(context.Background(), "digest", "/mod.wasm")
	if err != nil {
		t.Fatalf("WarmOne: %v", err)
	}
	if slot.WorkerKey == "" || slot.SocketPath == "" {
		t.Fatalf("slot incomplete: %+v", slot)
	}
	if len(spawner.warmed) != 1 {
		t.Fatalf("warmed = %v", spawner.warmed)
	}
}
