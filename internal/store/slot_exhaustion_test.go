package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

// A full network-slot pool is a capacity refusal, not a fault. A bank density
// run filled every metal worker's 256-slot pools and the creates past that
// failed with these errors as the catch-all 400, so a client could not tell
// "node full, retry" from "broken". Every exhaustion path must now match
// capacity.ErrCapacityExceeded and still match its own sentinel.
func TestSlotPoolExhaustionIsCapacityRefusal(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	cases := []struct {
		name     string
		sentinel error
		pool     string
		exhaust  func(t *testing.T, st *Store) error
	}{
		{
			name:     "containerd netns reserve",
			sentinel: ErrNoFreeContainerNetnsSlot,
			pool:     "container netns pool",
			exhaust: func(t *testing.T, st *Store) error {
				if err := st.SeedContainerNetnsSlot(ctx, "aerol-netns-0", now); err != nil {
					t.Fatal(err)
				}
				if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-a", now); err != nil {
					t.Fatal(err)
				}
				_, err := st.ReserveContainerNetnsSlot(ctx, "sb-b", now)
				return err
			},
		},
		{
			name:     "containerd netns prewarm",
			sentinel: ErrNoFreeContainerNetnsSlot,
			pool:     "container netns pool",
			exhaust: func(t *testing.T, st *Store) error {
				_, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
				return err
			},
		},
		{
			name:     "firecracker tap allocate",
			sentinel: ErrNoFreeFirecrackerTapSlot,
			pool:     "firecracker tap pool",
			exhaust: func(t *testing.T, st *Store) error {
				if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
					TapName: "fctap0", CIDR: "172.16.0.0/30", HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 3,
				}, now); err != nil {
					t.Fatal(err)
				}
				for _, id := range []string{"sb-fc-1", "sb-fc-2"} {
					if err := st.Create(ctx, sampleSandbox(id)); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := st.AllocateFirecrackerTapSlot(ctx, "sb-fc-1", now); err != nil {
					t.Fatal(err)
				}
				_, err := st.AllocateFirecrackerTapSlot(ctx, "sb-fc-2", now)
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.exhaust(t, newTestStore(t))
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("err = %v, want the pool's sentinel", err)
			}
			if !errors.Is(err, capacity.ErrCapacityExceeded) {
				t.Fatalf("err = %v, want a capacity refusal (errors.Is capacity.ErrCapacityExceeded)", err)
			}
			if pool, ok := capacity.SlotPoolExhausted(err); !ok || pool != tc.pool {
				t.Fatalf("SlotPoolExhausted = (%q, %t), want (%q, true)", pool, ok, tc.pool)
			}
		})
	}
}

// A warm-pool miss is not exhaustion: the create falls back to a cold slot,
// so ErrNoPooledContainerNetnsSlot must stay a plain miss.
func TestNoPooledNetnsSlotIsNotACapacityRefusal(t *testing.T) {
	st := newTestStore(t)
	_, err := st.ClaimPooledContainerNetnsSlot(context.Background(), "sb-x", time.Now())
	if !errors.Is(err, ErrNoPooledContainerNetnsSlot) {
		t.Fatalf("err = %v, want ErrNoPooledContainerNetnsSlot", err)
	}
	if errors.Is(err, capacity.ErrCapacityExceeded) {
		t.Fatal("a warm-pool miss must not read as a capacity refusal")
	}
}
