package store

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCountDistinctSandboxOwners backs the api-record flood control's
// shared-node rule (plans/identity-and-access.md §5.9, D14): operator-owned
// sandboxes ("") count as one owner, and the count stops at max.
func TestCountDistinctSandboxOwners(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	count := func(max int) int {
		t.Helper()
		n, err := s.CountDistinctSandboxOwners(ctx, max)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if got := count(2); got != 0 {
		t.Fatalf("empty node = %d owners", got)
	}
	now := time.Now().UTC()
	add := func(id, owner string) {
		t.Helper()
		if err := s.Create(ctx, &models.Sandbox{ID: id, Image: "alpine", Status: models.SandboxStatusStarted, OwnerRef: owner, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	add("sb-op-1", "")
	add("sb-op-2", "")
	if got := count(2); got != 1 {
		t.Fatalf("operator-only node = %d owners, want 1", got)
	}
	add("sb-a", "team:a")
	add("sb-b", "team:b")
	cases := []struct{ max, want int }{{2, 2}, {5, 3}, {1, 1}, {0, 1}}
	for _, c := range cases {
		if got := count(c.max); got != c.want {
			t.Errorf("count(max=%d) = %d, want %d", c.max, got, c.want)
		}
	}
}
