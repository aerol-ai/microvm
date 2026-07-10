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

// releaseRecorder captures park-reservation releases so the discard-path
// tests can prove no path leaks a park:<slot-id> admitter reservation.
type releaseRecorder struct {
	released []string
}

func (r *releaseRecorder) record(slotID string) { r.released = append(r.released, slotID) }

func TestPoolAcquireDeadSlotDestroysAndReleases(t *testing.T) {
	p := New(nil)
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	rec := &releaseRecorder{}
	p.SetParkReleaser(rec.record)
	key := testKey()
	p.RecordLoaded(&ParkedSlot{
		ID:      "park-dead",
		ImageID: "img-1",
		Key:     key,
		Handle:  &fakeHandle{alive: false},
	})

	_, err := p.Acquire(context.Background(), key, "img-1")
	if !errors.Is(err, ErrNoSlot) {
		t.Fatalf("acquire: %v", err)
	}
	if len(spawner.destroyed) != 1 || spawner.destroyed[0] != "park-dead" {
		t.Fatalf("dead slot not destroyed: %v", spawner.destroyed)
	}
	if len(rec.released) != 1 || rec.released[0] != "park-dead" {
		t.Fatalf("park reservation not released: %v", rec.released)
	}
	if p.Metrics().Stats().Orphans != 1 {
		t.Fatalf("orphans = %d", p.Metrics().Stats().Orphans)
	}
}

func TestPoolAcquireStaleImageReleasesReservation(t *testing.T) {
	p := New(nil)
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	rec := &releaseRecorder{}
	p.SetParkReleaser(rec.record)
	key := testKey()
	p.RecordLoaded(&ParkedSlot{
		ID:      "park-stale",
		ImageID: "old-digest",
		Key:     key,
		Handle:  &fakeHandle{alive: true},
	})

	if _, err := p.Acquire(context.Background(), key, "new-digest"); !errors.Is(err, ErrNoSlot) {
		t.Fatalf("acquire: %v", err)
	}
	if len(rec.released) != 1 || rec.released[0] != "park-stale" {
		t.Fatalf("park reservation not released: %v", rec.released)
	}
}

func TestPoolLRUEvictionReleasesReservations(t *testing.T) {
	p := New(nil)
	p.SetMaxImages(1)
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	rec := &releaseRecorder{}
	p.SetParkReleaser(rec.record)

	oldKey := Key{Image: "old:1", Runtime: models.RuntimeDocker}
	p.NoteTarget(oldKey)
	p.RecordLoaded(&ParkedSlot{ID: "park-old", Key: oldKey, Handle: &fakeHandle{alive: true}})

	// Second target overflows maxImages and evicts the LRU one.
	p.NoteTarget(Key{Image: "new:1", Runtime: models.RuntimeDocker})

	if len(spawner.destroyed) != 1 || spawner.destroyed[0] != "park-old" {
		t.Fatalf("evicted slot not destroyed: %v", spawner.destroyed)
	}
	if len(rec.released) != 1 || rec.released[0] != "park-old" {
		t.Fatalf("evicted reservation not released: %v", rec.released)
	}
}

func TestPoolReapIdleReleasesReservations(t *testing.T) {
	p := New(nil)
	p.SetIdleTTL(time.Millisecond)
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	rec := &releaseRecorder{}
	p.SetParkReleaser(rec.record)
	key := testKey()
	p.NoteTarget(key)
	p.RecordLoaded(&ParkedSlot{ID: "park-idle", Key: key, Handle: &fakeHandle{alive: true}})

	time.Sleep(2 * time.Millisecond)
	if n := p.ReapIdle(time.Now().UTC()); n != 1 {
		t.Fatalf("reaped = %d", n)
	}
	if len(rec.released) != 1 || rec.released[0] != "park-idle" {
		t.Fatalf("reaped reservation not released: %v", rec.released)
	}
}

func TestPoolReturnSlotKeepsSpawnCounter(t *testing.T) {
	p := New(nil)
	p.SetDefaultDepth(2)
	key := testKey()
	ks := key.KeyString()
	p.NoteTarget(key)

	slot := &ParkedSlot{ID: "park-ret", ImageID: "img-1", Key: key, Handle: &fakeHandle{alive: true}}
	p.RecordLoaded(slot)
	got, err := p.Acquire(context.Background(), key, "img-1")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// A refill is in flight while the duplicate-create loser returns the slot.
	p.MarkSpawning(ks)
	p.ReturnSlot(got)
	// ready=1 (returned) + spawning=1 with depth 2 → budget must be 0; a
	// decremented spawn counter here would over-park past depth.
	if b := p.SpawnBudget(ks); b != 0 {
		t.Fatalf("budget after return = %d", b)
	}

	again, err := p.Acquire(context.Background(), key, "img-1")
	if err != nil || again.ID != "park-ret" {
		t.Fatalf("reacquire: slot=%v err=%v", again, err)
	}
}

func TestPoolAcquireKeepsConcurrentRecordLoaded(t *testing.T) {
	// Regression for the unlock-relock race: a slot recorded while Acquire
	// was pruning a stale one must survive in the ready queue.
	p := New(nil)
	spawner := &fakeSpawner{}
	p.SetSpawner(spawner)
	key := testKey()
	p.RecordLoaded(&ParkedSlot{ID: "park-stale", ImageID: "old", Key: key, Handle: &fakeHandle{alive: true}})

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.RecordLoaded(&ParkedSlot{ID: "park-fresh", ImageID: "new", Key: key, Handle: &fakeHandle{alive: true}})
	}()
	<-done

	got, err := p.Acquire(context.Background(), key, "new")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if got.ID != "park-fresh" {
		t.Fatalf("slot = %q", got.ID)
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

// Boot-time pins are built bare (Key{Image, Runtime}) while create-path keys
// carry the metadata NormalizeCreateImageDistribution filled in. The two MUST
// collide in the ready map, or pinned slots are parked under a keystring no
// create ever computes — permanently unreachable warm capacity that, being
// pinned, is never idle-reaped either. This is a live-cluster regression:
// v0.5.29 nodes each carried two orphaned pinned alpine slots.
func TestKeyStringPinnedBareKeyMatchesNormalizedCreateKey(t *testing.T) {
	pinned := Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker}
	create := KeyFromRequest(models.CreateSandboxRequest{
		Image:                 "alpine:3.20",
		ImageRegistryRef:      "alpine:3.20",
		ImageDistributionMode: models.ImageDistributionExternalRegistry,
	}, models.RuntimeDocker)
	if pinned.KeyString() != create.KeyString() {
		t.Fatalf("pinned key %q != normalized create key %q", pinned.KeyString(), create.KeyString())
	}

	// AOCR refs and digests are identity-bearing: they must stay distinct.
	aocr := KeyFromRequest(models.CreateSandboxRequest{
		Image:                 "aocr.example/cluster/snapshots/base:latest",
		ImageRegistryRef:      "aocr.example/cluster/snapshots/base:latest",
		ImageDistributionMode: models.ImageDistributionAOCR,
	}, models.RuntimeDocker)
	if aocr.KeyString() == create.KeyString() {
		t.Fatal("aocr key collided with external-registry key")
	}
	digested := Key{Image: "alpine:3.20", ImageDigest: "sha256:abc", Runtime: models.RuntimeDocker}
	if digested.KeyString() == pinned.KeyString() {
		t.Fatal("digest-bearing key collided with bare key")
	}
}
