package containerdpool

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeHandle struct{ alive bool }

func (f *fakeHandle) Alive() bool                                         { return f.alive }
func (f *fakeHandle) Adopt(context.Context, string, string, string) error { return nil }
func (f *fakeHandle) Close() error                                        { return nil }

func TestPoolAcquireHit(t *testing.T) {
	p := New(nil)
	key := KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	p.NoteTarget(key)
	slot := &ParkedSlot{
		ID:      "park-ctd-1",
		ImageID: "img-1",
		Key:     key,
		Handle:  &fakeHandle{alive: true},
	}
	p.RecordLoaded(slot)
	got, err := p.Acquire(context.Background(), key, "img-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != slot.ID {
		t.Fatalf("slot=%q", got.ID)
	}
}

func TestPoolAcquireMiss(t *testing.T) {
	p := New(nil)
	key := KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	_, err := p.Acquire(context.Background(), key, "img-1")
	if !errors.Is(err, ErrNoSlot) {
		t.Fatalf("err=%v", err)
	}
}
