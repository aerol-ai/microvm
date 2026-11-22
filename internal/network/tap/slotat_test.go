package tap

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/tap/taphost"
)

// TestSlotAtMatchesSeed pins taphost.SlotAt, which the root helper uses to
// work a TAP's addresses out from its name (privilege mode split), to the
// pool's own layout: every slot the pool hands out is SlotAt of its index.
// A change to either layout that the other does not follow fails here.
func TestSlotAtMatchesSeed(t *testing.T) {
	for _, tc := range []struct {
		base string
		size int
	}{{"172.16.0.0/20", 37}, {"10.200.3.0/22", 12}, {"192.168.0.0/30", 1}} {
		st := newTestStore(t)
		p := New(st)
		ctx := context.Background()
		now := time.Now().UTC()
		if err := p.Seed(ctx, SeedConfig{BaseCIDR: tc.base, PoolSize: tc.size}, now); err != nil {
			t.Fatalf("seed %s: %v", tc.base, err)
		}
		seen := map[int]bool{}
		for i := range tc.size {
			got, err := p.Allocate(ctx, newTestSandbox(t, st, "sb-slotat-"+iToS(i)), now)
			if err != nil {
				t.Fatalf("%s allocate %d: %v", tc.base, i, err)
			}
			index, ok := taphost.IndexOf(got.TapName, tc.size)
			if !ok || seen[index] {
				t.Fatalf("%s: pool slot %q is no index of its own", tc.base, got.TapName)
			}
			seen[index] = true
			want, err := taphost.SlotAt(tc.base, tc.size, index)
			if err != nil || *got != want {
				t.Fatalf("%s: pool slot %+v, SlotAt(%d) = %+v, %v", tc.base, *got, index, want, err)
			}
		}
	}
}
