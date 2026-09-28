package dockerpool

import (
	"context"
	"testing"
)

func TestAcquireNilSlotInQueue(t *testing.T) {
	p := New(nil)
	key := testKey()
	ks := key.KeyString()
	p.mu.Lock()
	p.ready[ks] = []*ParkedSlot{nil, {ID: "alive", Key: key, Handle: &fakeHandle{alive: true}}}
	p.mu.Unlock()

	got, err := p.Acquire(context.Background(), key, "")
	if err != nil || got == nil || got.ID != "alive" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}
