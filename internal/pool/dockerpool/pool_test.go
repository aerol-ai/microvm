package dockerpool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeHandle struct {
	alive bool
}

func (f *fakeHandle) Alive() bool { return f.alive }

func (f *fakeHandle) Adopt(context.Context, string, string, string) error { return nil }

func (f *fakeHandle) Close() error { return nil }

type fakeSpawner struct {
	destroyed []string
}

func (f *fakeSpawner) Park(context.Context, string, Key) (*ParkedSlot, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeSpawner) DestroyParked(_ context.Context, slot *ParkedSlot) error {
	if slot != nil {
		f.destroyed = append(f.destroyed, slot.ID)
	}
	return nil
}

func testKey() Key {
	return Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker}
}

func TestPoolAcquireMissAndHit(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(1)
	key := testKey()
	p.NoteTarget(key)

	_, err := p.Acquire(context.Background(), key, "img-1")
	if !errors.Is(err, ErrNoSlot) {
		t.Fatalf("first acquire: %v", err)
	}
	if p.Metrics().Stats().Misses != 1 {
		t.Fatalf("misses = %d", p.Metrics().Stats().Misses)
	}

	slot := &ParkedSlot{
		ID:      "park-1",
		ImageID: "img-1",
		Key:     key,
		Handle:  &fakeHandle{alive: true},
	}
	p.RecordLoaded(slot)

	got, err := p.Acquire(context.Background(), key, "img-1")
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
	p := New(nil)
	p.SetDefaultDepth(2)
	key := testKey()
	ks := key.KeyString()
	p.NoteTarget(key)

	if b := p.SpawnBudget(ks); b != 2 {
		t.Fatalf("initial budget = %d", b)
	}
	p.RecordLoaded(&ParkedSlot{ID: "s1", Key: key, Handle: &fakeHandle{alive: true}})
	if b := p.SpawnBudget(ks); b != 1 {
		t.Fatalf("after one ready budget = %d", b)
	}
}

func TestPoolAcquireStaleImageDestroysSlot(t *testing.T) {
	p := New(nil)
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	key := testKey()
	slot := &ParkedSlot{
		ID:      "park-stale",
		ImageID: "old-digest",
		Key:     key,
		Handle:  &fakeHandle{alive: true},
	}
	p.RecordLoaded(slot)

	_, err := p.Acquire(context.Background(), key, "new-digest")
	if !errors.Is(err, ErrNoSlot) {
		t.Fatalf("acquire: %v", err)
	}
	if len(spawner.destroyed) != 1 || spawner.destroyed[0] != "park-stale" {
		t.Fatalf("destroyed = %v", spawner.destroyed)
	}
	if p.Metrics().Stats().StaleImages != 1 {
		t.Fatalf("stale images = %d", p.Metrics().Stats().StaleImages)
	}
}

func TestPoolReapIdleDestroysReadySlots(t *testing.T) {
	p := New(nil)
	p.SetIdleTTL(time.Millisecond)
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	key := testKey()
	p.NoteTarget(key)
	p.RecordLoaded(&ParkedSlot{
		ID:     "park-idle",
		Key:    key,
		Handle: &fakeHandle{alive: true},
	})

	time.Sleep(2 * time.Millisecond)
	if n := p.ReapIdle(time.Now().UTC()); n != 1 {
		t.Fatalf("reaped = %d", n)
	}
	if len(spawner.destroyed) != 1 {
		t.Fatalf("destroyed = %v", spawner.destroyed)
	}
}

func TestKeyFromRequestAndKeyString(t *testing.T) {
	key := KeyFromRequest(models.CreateSandboxRequest{
		Image:                 "ubuntu:22.04",
		ImageDigest:           "sha256:abc",
		ImageRegistryRef:      "registry.example/ubuntu",
		ImageDistributionMode: "pull",
	}, models.RuntimeDocker)
	if key.Image != "ubuntu:22.04" || key.Runtime != models.RuntimeDocker {
		t.Fatalf("key = %+v", key)
	}
	if key.KeyString() == "" {
		t.Fatal("empty key string")
	}
}
