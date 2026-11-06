package dockerpool

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// imageAt is a resolver whose answer the test moves, as a retag would.
type imageAt struct {
	id    string
	err   error
	calls int
}

func (r *imageAt) resolve(context.Context, Key) (string, error) {
	r.calls++
	return r.id, r.err
}

func parkImage(p *Pool, id, imageID string, key Key) {
	p.RecordLoaded(&ParkedSlot{ID: id, ImageID: imageID, Key: key, Handle: &fakeHandle{alive: true}})
}

func replacePool(t *testing.T, asUsed bool, depth int) (*Pool, *fakeClock, *imageAt, *fakeSpawner, Key) {
	t.Helper()
	p := New(nil)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.now = clk.now
	destroyer := &fakeSpawner{}
	p.SetSpawner(destroyer)
	img := &imageAt{id: "sha256:old"}
	p.SetImageResolver(img.resolve)
	key := entryKey("python:3.12")
	p.SetConfigured([]Configured{{Key: key, Depth: depth, ReplaceAsUsed: asUsed}})
	return p, clk, img, destroyer, key
}

// TestReplaceNowSwapsOldSlotsAtOnce: when the tag moves, the next refill
// tick destroys every old-image slot and parks fresh ones, and none of the
// old ones is handed out in between, even to a caller (containerd) that
// passes no image of its own.
func TestReplaceNowSwapsOldSlotsAtOnce(t *testing.T) {
	p, clk, img, destroyer, key := replacePool(t, false, 2)
	parkImage(p, "old-1", "sha256:old", key)
	parkImage(p, "old-2", "sha256:old", key)
	spawner := &refillSpawner{}
	tick := func() { p.refillTick(context.Background(), RefillConfig{}, spawner, &refillGate{canPark: true}) }
	tick()
	if len(destroyer.destroyed) != 0 || len(spawner.slots) != 0 {
		t.Fatal("slots on the current image are left alone")
	}
	img.id = "sha256:new"
	clk.advance(imageCheckEvery)
	if st := p.ConfiguredStatus(); st[0].Outdated != 0 {
		t.Fatal("outdated is only known after the next lookup")
	}
	tick()
	if !reflect.DeepEqual(destroyer.destroyed, []string{"old-1", "old-2"}) || len(spawner.slots) != 2 {
		t.Fatalf("destroyed %v, parked %d: want both old slots swapped on one tick", destroyer.destroyed, len(spawner.slots))
	}
	if p.Metrics().Stats().Replaced != 2 {
		t.Fatalf("replaced = %d", p.Metrics().Stats().Replaced)
	}
	// A late old-image slot (parked from a stale cache) is never handed out.
	parkImage(p, "late-old", "sha256:old", key)
	for i := 0; i < 3; i++ {
		got, err := p.Acquire(context.Background(), key, "")
		if err != nil {
			break
		}
		if got.ImageID == "sha256:old" {
			t.Fatalf("handed out %s on the old image", got.ID)
		}
	}
}

// TestReplaceAsUsedHandsOldSlotsOutOldestFirst: old slots stay, are
// counted as outdated, and are handed out first (even when the caller
// names the new image); each one used is refilled on the new image.
func TestReplaceAsUsedHandsOldSlotsOutOldestFirst(t *testing.T) {
	p, clk, img, destroyer, key := replacePool(t, true, 2)
	parkImage(p, "old-1", "sha256:old", key)
	parkImage(p, "old-2", "sha256:old", key)
	img.id = "sha256:new"
	spawner := &refillSpawner{}
	p.refillTick(context.Background(), RefillConfig{}, spawner, &refillGate{canPark: true})
	if len(destroyer.destroyed) != 0 || len(spawner.slots) != 0 {
		t.Fatal("replace_as_used keeps old slots and parks nothing while the pool is full")
	}
	if st := p.ConfiguredStatus(); st[0].Outdated != 2 || st[0].Ready != 2 {
		t.Fatalf("status = %+v, want two outdated", st)
	}
	got, err := p.Acquire(context.Background(), key, "sha256:new")
	if err != nil || got.ID != "old-1" {
		t.Fatalf("acquire = %v %v, want the oldest old slot", got, err)
	}
	clk.advance(imageCheckEvery)
	p.refillTick(context.Background(), RefillConfig{}, spawner, &refillGate{canPark: true})
	if len(spawner.slots) != 1 {
		t.Fatalf("one used, one refilled: parked %d", len(spawner.slots))
	}
	// The refill's slot carries whatever the engine parked; mark it new.
	spawner.slots[0].ImageID = "sha256:new"
	if st := p.ConfiguredStatus(); st[0].Outdated != 1 || st[0].Ready != 2 {
		t.Fatalf("status = %+v, want one outdated left", st)
	}
	// A shrink gives back the outdated slot before the current one.
	p.SetConfigured([]Configured{{Key: key, Depth: 1, ReplaceAsUsed: true}})
	p.destroySlots(context.Background(), p.trimExcess())
	if !reflect.DeepEqual(destroyer.destroyed, []string{"old-2"}) {
		t.Fatalf("trim gave back %v, want the old slot", destroyer.destroyed)
	}
	if st := p.ConfiguredStatus(); st[0].Outdated != 0 || st[0].Ready != 1 {
		t.Fatalf("status = %+v", st)
	}
}

// TestImageCheckGuards: no resolver means no check; a failed or empty
// lookup keeps the last answer instead of destroying slots on a guess;
// lookups are throttled to one per interval however often refill is
// kicked; and a key that is not an entry keeps the engine's own check.
func TestImageCheckGuards(t *testing.T) {
	p := New(nil)
	key := entryKey("python:3.12")
	p.SetConfigured([]Configured{{Key: key, Depth: 1}})
	parkImage(p, "s1", "sha256:a", key)
	if p.refreshImages(context.Background()) != nil {
		t.Fatal("no resolver: no check")
	}

	p2, clk, img, _, key2 := replacePool(t, false, 1)
	parkImage(p2, "s1", "sha256:old", key2)
	img.err = errors.New("engine busy")
	if got := p2.refreshImages(context.Background()); got != nil {
		t.Fatalf("a failed lookup destroyed %v", got)
	}
	img.err, img.id = nil, ""
	clk.advance(imageCheckEvery)
	if got := p2.refreshImages(context.Background()); got != nil || p2.currentImage[key2.KeyString()] != "" {
		t.Fatalf("an empty answer is no answer: %v", got)
	}
	img.id = "sha256:new"
	calls := img.calls
	if got := p2.refreshImages(context.Background()); got != nil || img.calls != calls {
		t.Fatal("a second check inside the interval must not look up")
	}
	clk.advance(imageCheckEvery)
	if got := p2.refreshImages(context.Background()); len(got) != 1 {
		t.Fatalf("after the interval the retag is seen: %v", got)
	}

	// A target that is not an entry: Acquire's own image decides, as before.
	other := entryKey("node:22")
	p2.NoteTarget(other)
	parkImage(p2, "n1", "sha256:x", other)
	if got, err := p2.Acquire(context.Background(), other, ""); err != nil || got.ID != "n1" {
		t.Fatalf("a non-entry key with no image given is handed out: %v %v", got, err)
	}

	// A delete forgets the entry's current image.
	p2.SetConfigured(nil)
	if _, ok := p2.currentImage[key2.KeyString()]; ok {
		t.Fatal("a deleted entry's current image must be dropped")
	}
}

// deletingResolver deletes the entry while its lookup runs.
func TestImageCheckEntryDeletedWhileResolving(t *testing.T) {
	p := New(nil)
	key := entryKey("python:3.12")
	p.SetConfigured([]Configured{{Key: key, Depth: 1}})
	p.SetImageResolver(func(context.Context, Key) (string, error) {
		p.SetConfigured(nil)
		return "sha256:new", nil
	})
	if got := p.refreshImages(context.Background()); got != nil || len(p.currentImage) != 0 {
		t.Fatalf("a deleted entry is skipped: %v %v", got, p.currentImage)
	}
}

// TestEnvPinFallbackForgetsTheEntrysImage: deleting an entry whose image is
// also an env pin keeps the key warm at the default depth. It must drop the
// image ID the entry last read (nothing reads it again, and Acquire falls
// back to it), and give back the slots the entry held above that depth.
func TestEnvPinFallbackForgetsTheEntrysImage(t *testing.T) {
	p, clk, img, destroyer, key := replacePool(t, false, 3)
	p.SetDefaultDepth(1)
	p.PinTarget(key)
	for _, id := range []string{"s1", "s2", "s3"} {
		parkImage(p, id, "sha256:old", key)
	}
	clk.advance(imageCheckEvery)
	if got := p.refreshImages(context.Background()); got != nil || p.currentImage[key.KeyString()] != "sha256:old" {
		t.Fatalf("setup: %v %v", got, p.currentImage)
	}

	p.SetConfigured(nil)
	if _, ok := p.currentImage[key.KeyString()]; ok {
		t.Fatal("the env pin kept the deleted entry's image ID")
	}
	var ready []string
	for _, slot := range p.ready[key.KeyString()] {
		ready = append(ready, slot.ID)
	}
	if got := ready; !reflect.DeepEqual(got, []string{"s1"}) {
		t.Fatalf("ready after the fallback = %v, want the oldest slot only", got)
	}
	if !reflect.DeepEqual(destroyer.destroyed, []string{"s2", "s3"}) {
		t.Fatalf("destroyed = %v, want the two above the default depth", destroyer.destroyed)
	}
	if _, ok := p.targets[key.KeyString()]; !ok {
		t.Fatal("the env pin must stay a target")
	}

	// The tag moves; the env pin's next slot runs the new image. Acquire
	// with no image given (containerd) must hand both out, not judge the
	// new one stale against the entry's last answer.
	img.id = "sha256:new"
	parkImage(p, "n1", "sha256:new", key)
	for _, want := range []string{"s1", "n1"} {
		got, err := p.Acquire(context.Background(), key, "")
		if err != nil || got == nil || got.ID != want {
			t.Fatalf("Acquire = %v %v, want %s", got, err, want)
		}
	}
}
